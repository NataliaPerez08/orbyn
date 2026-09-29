//! Native WS-Man/WinRM transport for the Windows host collector (v0.3).
//!
//! Implements the WS-Management SOAP protocol against the Windows shell
//! resource — shell create, command, receive, delete — over HTTPS through
//! the `curl` binary, consistent with the rest of the collector surface
//! (the NetBox importer drives `curl` the same way).
//!
//! Authentication is HTTP Basic over HTTPS, WinRM's documented secure
//! configuration for Basic auth. The password:
//! - is sourced from `ORBYN_WINRM_PASSWORD` or stdin at the CLI level and
//!   never from process arguments;
//! - lives in memory only for the duration of the run — Orbyn persists no
//!   credentials;
//! - is streamed to curl through stdin as a config file (`-K -`), so it
//!   never appears in argv, logs, or on disk;
//! - is registered with the redactor and stripped from child environments.
//!
//! The PowerShell probe travels as `-EncodedCommand` (base64 of UTF-16LE),
//! so no remote shell ever re-parses the probe text. Every request carries
//! a bounded operation timeout and the receive loop is capped, so a hung
//! or hostile endpoint cannot stall a discovery job indefinitely.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use tokio::process::Command;

use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES, MAX_STDOUT_CAPTURE_BYTES};

use super::credentials::CredentialProfile;

/// SOAP 1.2 content type the WS-Man endpoint expects.
const SOAP_CONTENT_TYPE: &str = "application/soap+xml;charset=UTF-8";

const NS_SHELL: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
const SHELL_RESOURCE_URI: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
const ACTION_CREATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
const ACTION_COMMAND: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
const ACTION_RECEIVE: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
const ACTION_DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

/// Remote PowerShell binary invoked through the shell resource.
const POWERSHELL_BINARY: &str = "powershell.exe";
/// WS-Man operation timeout advertised per request; the transport's own
/// curl timeout must stay above it.
const OPERATION_TIMEOUT: &str = "PT30S";
/// Whole-process timeout for one WS-Man request.
const WINRM_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum receive round trips before the transport gives up on a shell
/// that never reports `Done`.
const MAX_RECEIVES: usize = 16;

/// Executes PowerShell scripts on Windows hosts through the native
/// WS-Man/WinRM protocol over HTTPS.
pub struct WinRmTransport {
    binary: String,
    profile: CredentialProfile,
    password: String,
    insecure: bool,
}

// Manual Debug: the struct carries the password in memory and must never
// leak it through debug logs (SECURITY.md credential rules).
impl std::fmt::Debug for WinRmTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinRmTransport")
            .field("username", &self.profile.username)
            .field("port", &self.profile.port)
            .field("insecure", &self.insecure)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl WinRmTransport {
    /// Create a transport for `profile` (login user + HTTPS port) with the
    /// Basic-auth `password` held in memory for the run only.
    pub fn new(
        profile: CredentialProfile,
        password: Option<String>,
        insecure: bool,
    ) -> Result<Self> {
        let password = password.ok_or_else(|| {
            anyhow!(
                "the WinRM transport requires a password: pass --winrm-password - \
                 (reads one line from stdin) or set ORBYN_WINRM_PASSWORD"
            )
        })?;
        if profile.username.is_empty() {
            bail!("the WinRM transport requires a login user (--user)");
        }
        if profile.username.contains(['\n', '\r', '\0']) || password.contains(['\n', '\r', '\0']) {
            // Newlines would split the curl config streamed to stdin
            // (config injection, mirroring the resolve_secret rules).
            bail!("WinRM credentials cannot contain newlines or NUL bytes");
        }
        Ok(Self {
            binary: std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string()),
            profile,
            password,
            insecure,
        })
    }

    /// Run a read-only PowerShell `script` on `host`, returning its stdout.
    ///
    /// The full WS-Man lifecycle runs here: create shell, send the encoded
    /// command, receive output until `Done`, then delete the shell
    /// (best-effort, also on failure).
    pub async fn run(&self, host: IpAddr, script: &str) -> Result<String> {
        let url = endpoint(host, self.profile.port);
        let shell_id = self.create_shell(&url).await?;
        let result = self.execute(&url, &shell_id, script).await;
        // Best-effort cleanup: a failed delete must not mask the probe result.
        let _ = self.delete_shell(&url, &shell_id).await;
        result
    }

    async fn create_shell(&self, url: &str) -> Result<String> {
        let body = self.post(url, &create_envelope(url)).await?;
        parse_shell_id(&body).ok_or_else(|| {
            anyhow!(
                "the WinRM endpoint did not return a shell id{}",
                fault_suffix(&body)
            )
        })
    }

    async fn send_command(&self, url: &str, shell_id: &str, script: &str) -> Result<String> {
        let body = self
            .post(url, &command_envelope(url, shell_id, script))
            .await?;
        parse_command_id(&body).ok_or_else(|| {
            anyhow!(
                "the WinRM endpoint did not accept the command{}",
                fault_suffix(&body)
            )
        })
    }

    async fn delete_shell(&self, url: &str, shell_id: &str) -> Result<()> {
        self.post(url, &delete_envelope(url, shell_id)).await?;
        Ok(())
    }

    async fn execute(&self, url: &str, shell_id: &str, script: &str) -> Result<String> {
        let command_id = self.send_command(url, shell_id, script).await?;

        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr = String::new();
        let mut exit_code: Option<i32> = None;
        for _ in 0..MAX_RECEIVES {
            let body = self
                .post(url, &receive_envelope(url, shell_id, &command_id))
                .await?;
            let outcome = parse_receive_response(&body)?;
            stdout.extend_from_slice(&outcome.stdout);
            stderr.push_str(&String::from_utf8_lossy(&outcome.stderr));
            if stdout.len() as u64 > MAX_STDOUT_CAPTURE_BYTES {
                bail!(
                    "WinRM shell output exceeded the {} byte capture limit",
                    MAX_STDOUT_CAPTURE_BYTES
                );
            }
            match outcome.state {
                ReceiveState::Pending => continue,
                ReceiveState::Done(code) => {
                    exit_code = Some(code);
                    break;
                }
            }
        }

        let Some(code) = exit_code else {
            bail!(
                "the WinRM shell did not report completion within \
                 {MAX_RECEIVES} receive rounds"
            );
        };
        if code != 0 {
            bail!(
                "powershell exited with {code} on the WinRM shell: {}",
                stderr.trim()
            );
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// POST one SOAP envelope, returning the response body. Non-200 replies
    /// surface the SOAP fault when the endpoint sent one.
    async fn post(&self, url: &str, envelope: &str) -> Result<String> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-sS")
            // The HTTP status is appended to stdout (3 digits) so auth and
            // endpoint failures are distinguishable without -f, which would
            // discard the SOAP fault body.
            .arg("-w")
            .arg("%{http_code}")
            .arg("-H")
            .arg(SOAP_CONTENT_TYPE)
            // Credentials arrive through a config file on stdin, never argv.
            .arg("-K")
            .arg("-");
        if self.insecure {
            cmd.arg("--insecure");
        }
        cmd.arg("--data-binary")
            .arg(envelope)
            .arg(url)
            // Secret-bearing variables never reach the child environment
            // (audit OY-02): a hijacked curl must not be able to read the
            // community, the NetBox token, the WinRM password or the
            // database URL password.
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_PROMETHEUS_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .context("failed to start curl; is it installed?")?;

        let config = curl_config(&self.profile.username, &self.password);
        let captured = run_captured(
            child,
            Some(&config),
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            WINRM_REQUEST_TIMEOUT,
            format!("curl timed out against {url}"),
        )
        .await?;

        if !captured.status.success() {
            return Err(anyhow!(
                "curl exited with {} against {url}: {}",
                captured.status,
                captured.stderr.trim()
            ));
        }

        let Some((body, status)) = split_http_status(&captured.stdout) else {
            bail!("malformed curl response from {url}: no HTTP status trailer");
        };
        match status {
            "200" => Ok(body.to_string()),
            "401" => Err(anyhow!(
                "WinRM authentication failed for {} against {url} (HTTP 401)",
                self.profile.username
            )),
            _ => {
                if let Some(fault) = parse_soap_fault(body) {
                    bail!("the WinRM endpoint returned HTTP {status}: {fault}");
                }
                bail!(
                    "the WinRM endpoint returned HTTP {status}: {}",
                    excerpt(body)
                );
            }
        }
    }
}

/// The `https://host:port/wsman` endpoint for a target.
fn endpoint(host: IpAddr, port: u16) -> String {
    match host {
        IpAddr::V4(v4) => format!("https://{v4}:{port}/wsman"),
        // IPv6 literals need brackets in URLs.
        IpAddr::V6(v6) => format!("https://[{v6}]:{port}/wsman"),
    }
}

/// The curl config streamed to stdin: `user = "user:password"` with the
/// values escaped for curl's double-quoted config syntax.
fn curl_config(username: &str, password: &str) -> String {
    format!(
        "user = \"{}:{}\"\n",
        escape_config_value(username),
        escape_config_value(password)
    )
}

/// Escape a value for curl's double-quoted config syntax (`\\` and `\"`).
fn escape_config_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Split curl stdout into `(body, status)` using the 3-digit `-w` trailer.
fn split_http_status(out: &str) -> Option<(&str, &str)> {
    if out.len() < 3 {
        return None;
    }
    let (body, status) = out.split_at(out.len() - 3);
    if !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((body, status))
}

/// Encode a PowerShell script for `-EncodedCommand`: base64 of UTF-16LE.
pub fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Build a WS-Man envelope with the shared SOAP/WS-Addressing headers.
fn envelope(action: &str, to: &str, shell_id: Option<&str>, body: &str) -> String {
    let selector = match shell_id {
        Some(id) => {
            format!("<w:SelectorSet><w:Selector Name=\"ShellId\">{id}</w:Selector></w:SelectorSet>")
        }
        None => String::new(),
    };
    let message_id = uuid::Uuid::new_v4();
    format!(
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
         xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" \
         xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">\
         <s:Header>\
         <a:Action s:mustUnderstand=\"1\">{action}</a:Action>\
         <a:To s:mustUnderstand=\"1\">{to}</a:To>\
         <w:ResourceURI s:mustUnderstand=\"1\">{SHELL_RESOURCE_URI}</w:ResourceURI>\
         <a:MessageID>uuid:{message_id}</a:MessageID>\
         <a:ReplyTo><a:Address s:mustUnderstand=\"1\">\
         http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous\
         </a:Address></a:ReplyTo>\
         <w:OperationTimeout>{OPERATION_TIMEOUT}</w:OperationTimeout>\
         <w:MaxEnvelopeSize s:mustUnderstand=\"0\">153600</w:MaxEnvelopeSize>\
         <w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"0\"/>\
         <p:DataLocale xml:lang=\"en-US\" s:mustUnderstand=\"0\"/>\
         {selector}\
         </s:Header>\
         <s:Body>{body}</s:Body>\
         </s:Envelope>"
    )
}

/// `wxf:Create` against the Windows cmd shell resource.
fn create_envelope(to: &str) -> String {
    let body = format!(
        "<rsp:Shell xmlns:rsp=\"{NS_SHELL}\">\
         <rsp:InputStreams>stdin</rsp:InputStreams>\
         <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>\
         </rsp:Shell>"
    );
    envelope(ACTION_CREATE, to, None, &body)
}

/// `shell/Command` carrying the probe as an encoded PowerShell command.
fn command_envelope(to: &str, shell_id: &str, script: &str) -> String {
    let body = format!(
        "<rsp:CommandLine xmlns:rsp=\"{NS_SHELL}\">\
         <rsp:Command>{POWERSHELL_BINARY}</rsp:Command>\
         <rsp:Arguments>-NoProfile -EncodedCommand {}</rsp:Arguments>\
         </rsp:CommandLine>",
        encode_command(script)
    );
    envelope(ACTION_COMMAND, to, Some(shell_id), &body)
}

/// `shell/Receive` asking for both output streams of a command.
fn receive_envelope(to: &str, shell_id: &str, command_id: &str) -> String {
    let body = format!(
        "<rsp:Receive xmlns:rsp=\"{NS_SHELL}\">\
         <rsp:DesiredStream CommandId=\"{command_id}\">stdout stderr</rsp:DesiredStream>\
         </rsp:Receive>"
    );
    envelope(ACTION_RECEIVE, to, Some(shell_id), &body)
}

/// `wxf:Delete` closing the shell.
fn delete_envelope(to: &str, shell_id: &str) -> String {
    envelope(ACTION_DELETE, to, Some(shell_id), "")
}

/// The local part of a possibly prefixed XML name (`rsp:Stream` -> `Stream`).
fn local_name(name: &str) -> &str {
    match name.rsplit_once(':') {
        Some((_, local)) => local,
        None => name,
    }
}

/// The local name of any element event (start/end/empty) as a string slice.
fn element_local_name(name: &[u8]) -> &str {
    local_name(std::str::from_utf8(name).unwrap_or(""))
}

/// Decoded and entity-unescaped text of a text event.
fn text_content(t: &quick_xml::events::BytesText<'_>) -> String {
    let decoded = t.decode().unwrap_or_default();
    quick_xml::escape::unescape(&decoded)
        .unwrap_or_default()
        .into_owned()
}

/// An attribute value by local name (`Name`, `State`), decoded.
fn attr_value(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| local_name(std::str::from_utf8(a.key.as_ref()).unwrap_or("")) == name)
        .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
}

/// Text content of the first element matching `name` (and, optionally, an
/// attribute `attr_name="attr_value"`), ignoring namespace prefixes.
fn first_element_text(
    xml: &str,
    name: &str,
    attr_name: Option<&str>,
    attr_value_expected: Option<&str>,
) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut capture = false;
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let attr_matches = match (attr_name, attr_value_expected) {
                    (Some(n), Some(v)) => attr_value(&e, n).as_deref() == Some(v),
                    _ => true,
                };
                if local_name(element_local_name(e.name().as_ref())) == name && attr_matches {
                    capture = true;
                    text.clear();
                }
            }
            Ok(Event::Text(t)) if capture => {
                text.push_str(&text_content(&t));
            }
            Ok(Event::End(e)) if capture => {
                if local_name(element_local_name(e.name().as_ref())) == name {
                    return (!text.is_empty()).then_some(text);
                }
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            Ok(_) => {}
        }
    }
}

/// The `ShellId` selector of a `wxf:Create` response.
pub fn parse_shell_id(xml: &str) -> Option<String> {
    first_element_text(xml, "Selector", Some("Name"), Some("ShellId"))
}

/// The `CommandId` of a `shell/Command` response.
pub fn parse_command_id(xml: &str) -> Option<String> {
    first_element_text(xml, "CommandId", None, None)
}

/// Completion state of a command as reported by a `shell/Receive` response.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveState {
    /// More output is available; receive again.
    #[default]
    Pending,
    /// The command finished with this exit code.
    Done(i32),
}

/// Decoded streams and state of one `shell/Receive` response.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReceiveOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub state: ReceiveState,
}

/// Parse a `shell/Receive` response: base64 `Stream` elements for stdout
/// and stderr plus the `CommandState` (`Done` with `ExitCode`, or
/// `Pending`). Namespace prefixes are ignored.
pub fn parse_receive_response(xml: &str) -> Result<ReceiveOutcome> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut outcome = ReceiveOutcome::default();
    let mut current_stream: Option<String> = None;
    let mut in_exit_code = false;
    let mut exit_code_text = String::new();
    let mut state_attr: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match local_name(element_local_name(e.name().as_ref())) {
                "Stream" => {
                    current_stream = attr_value(&e, "Name").filter(|v| !v.is_empty());
                }
                "CommandState" => {
                    state_attr = attr_value(&e, "State");
                }
                "ExitCode" => {
                    in_exit_code = true;
                    exit_code_text.clear();
                }
                _ => {}
            },
            // Empty elements carry no text: only the attribute-only
            // CommandState matters here (an empty Stream or ExitCode has
            // no content to decode).
            Ok(Event::Empty(e)) => {
                if local_name(element_local_name(e.name().as_ref())) == "CommandState" {
                    state_attr = attr_value(&e, "State");
                }
            }
            Ok(Event::Text(t)) => {
                let text = text_content(&t);
                if current_stream.is_some() {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(text.as_bytes())
                        .context("decoding a WinRM output stream")?;
                    match current_stream.as_deref() {
                        Some("stdout") => outcome.stdout.extend_from_slice(&bytes),
                        Some("stderr") => outcome.stderr.extend_from_slice(&bytes),
                        _ => {}
                    }
                } else if in_exit_code {
                    exit_code_text.push_str(&text);
                }
            }
            Ok(Event::End(e)) => match local_name(element_local_name(e.name().as_ref())) {
                "Stream" => current_stream = None,
                "ExitCode" => in_exit_code = false,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => bail!("parsing the WinRM receive response: {e}"),
            Ok(_) => {}
        }
    }

    if let Some(state) = state_attr {
        match local_name(&state) {
            "Done" => {
                let code: i32 = exit_code_text
                    .trim()
                    .parse()
                    .context("the WinRM shell reported Done without a parsable exit code")?;
                outcome.state = ReceiveState::Done(code);
            }
            "Pending" => outcome.state = ReceiveState::Pending,
            other => bail!("unknown WinRM command state '{other}'"),
        }
    }
    Ok(outcome)
}

/// A SOAP 1.2 fault extracted from an error response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapFault {
    pub code: String,
    pub subcode: Option<String>,
    pub reason: String,
}

impl std::fmt::Display for SoapFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.subcode {
            Some(subcode) => write!(f, "{} ({subcode}): {}", self.code, self.reason),
            None => write!(f, "{}: {}", self.code, self.reason),
        }
    }
}

/// Parse the `s:Fault` of an error response, if present.
pub fn parse_soap_fault(xml: &str) -> Option<SoapFault> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut in_fault = false;
    let mut values: Vec<String> = Vec::new();
    let mut reason = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if local_name(element_local_name(e.name().as_ref())) == "Fault" {
                    in_fault = true;
                }
            }
            Ok(Event::Text(t)) if in_fault => {
                let text = text_content(&t);
                if !text.is_empty() && values.len() < 2 {
                    values.push(text.to_string());
                } else if text.len() > reason.len() {
                    // The Reason text is the longest text node in the fault.
                    reason = text.to_string();
                }
            }
            Ok(Event::End(e)) => {
                if local_name(element_local_name(e.name().as_ref())) == "Fault" {
                    return Some(SoapFault {
                        code: values.first().cloned().unwrap_or_default(),
                        subcode: values.get(1).cloned(),
                        reason,
                    });
                }
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            Ok(_) => {}
        }
    }
}

/// A one-line excerpt of an unexpected response body for error messages.
fn excerpt(body: &str) -> String {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 200 {
        format!("{}...", &collapsed[..200])
    } else {
        collapsed
    }
}

/// Append the SOAP fault to an error message when the body carries one.
fn fault_suffix(body: &str) -> String {
    match parse_soap_fault(body) {
        Some(fault) => format!(": {fault}"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://10.0.0.20:5986/wsman";

    const CREATE_RESPONSE: &str = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
        <s:Header/><s:Body>\
        <rsp:Shell xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\" \
        xmlns:wsmid=\"http://schemas.dmtf.org/wbem/cim/1/cim-base\">\
        <wsmid:Selector Name=\"ShellId\">1A2B3C4D-1111-2222-3333-444455556666</wsmid:Selector>\
        <rsp:ResourceId>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/1A2B3C4D</rsp:ResourceId>\
        <rsp:InputStreams>stdin</rsp:InputStreams>\
        <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>\
        </rsp:Shell></s:Body></s:Envelope>";

    const COMMAND_RESPONSE: &str =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
        <s:Body><rsp:CommandResponse \
        xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">\
        <rsp:CommandId>AAAA-BBBB-CCCC</rsp:CommandId>\
        </rsp:CommandResponse></s:Body></s:Envelope>";

    fn receive_response(state: &str, exit_code: Option<&str>, stdout_b64: &str) -> String {
        let exit = match exit_code {
            Some(code) => format!("<rsp:ExitCode>{code}</rsp:ExitCode>"),
            None => String::new(),
        };
        format!(
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>\
             <rsp:ReceiveResponse xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">\
             <rsp:Stream Name=\"stdout\" CommandId=\"CMD\">{stdout_b64}</rsp:Stream>\
             <rsp:Stream Name=\"stderr\" CommandId=\"CMD\">c3RkZXJy</rsp:Stream>\
             <rsp:CommandState CommandId=\"CMD\" State=\"rsp:{state}\">{exit}</rsp:CommandState>\
             </rsp:ReceiveResponse></s:Body></s:Envelope>"
        )
    }

    #[test]
    fn endpoint_formats_ipv4_and_ipv6() {
        assert_eq!(
            endpoint("10.0.0.20".parse().unwrap(), 5986),
            "https://10.0.0.20:5986/wsman"
        );
        assert_eq!(
            endpoint("2001:db8::1".parse().unwrap(), 5986),
            "https://[2001:db8::1]:5986/wsman"
        );
    }

    #[test]
    fn curl_config_carries_credentials_escaped() {
        assert_eq!(
            curl_config("Administrator", "s3cret"),
            "user = \"Administrator:s3cret\"\n"
        );
        // Quotes and backslashes must survive curl's config syntax.
        assert_eq!(
            curl_config("ad\\min", "pa\"ss\\word"),
            "user = \"ad\\\\min:pa\\\"ss\\\\word\"\n"
        );
    }

    #[test]
    fn split_http_status_separates_body_and_trailer() {
        assert_eq!(split_http_status("body200"), Some(("body", "200")));
        assert_eq!(split_http_status("200"), Some(("", "200")));
        assert_eq!(split_http_status(""), None);
        assert_eq!(split_http_status("20"), None);
        assert_eq!(split_http_status("body2x0"), None);
    }

    #[test]
    fn encoded_command_round_trips_through_utf16le() {
        let encoded = encode_command("Write-Output 'orbyn'; $x = 1");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .expect("valid base64");
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(
            String::from_utf16(&units).unwrap(),
            "Write-Output 'orbyn'; $x = 1"
        );
    }

    #[test]
    fn create_envelope_targets_the_shell_resource() {
        let xml = create_envelope(URL);
        assert!(xml.contains(
            "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>"
        ));
        assert!(xml.contains(&format!(
            "<w:ResourceURI s:mustUnderstand=\"1\">{SHELL_RESOURCE_URI}</w:ResourceURI>"
        )));
        assert!(xml.contains(&format!("<a:To s:mustUnderstand=\"1\">{URL}</a:To>")));
        assert!(xml.contains("<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"));
        assert!(!xml.contains("SelectorSet"), "no shell exists yet");
    }

    #[test]
    fn command_envelope_carries_shell_selector_and_encoded_script() {
        let xml = command_envelope(URL, "SHELL-1", "Get-CimInstance Win32_OperatingSystem");
        assert!(xml.contains("shell/Command</a:Action>"));
        assert!(xml.contains("<w:Selector Name=\"ShellId\">SHELL-1</w:Selector>"));
        assert!(xml.contains("<rsp:Command>powershell.exe</rsp:Command>"));
        assert!(xml.contains("-NoProfile -EncodedCommand "));
        // The script must travel encoded, never as raw text.
        assert!(!xml.contains("Get-CimInstance"));
    }

    #[test]
    fn receive_and_delete_envelopes_reference_the_shell() {
        let receive = receive_envelope(URL, "SHELL-1", "CMD-9");
        assert!(receive.contains("shell/Receive</a:Action>"));
        assert!(receive
            .contains("<rsp:DesiredStream CommandId=\"CMD-9\">stdout stderr</rsp:DesiredStream>"));
        assert!(receive.contains("<w:Selector Name=\"ShellId\">SHELL-1</w:Selector>"));

        let delete = delete_envelope(URL, "SHELL-1");
        assert!(delete.contains("transfer/Delete</a:Action>"));
        assert!(delete.contains("<w:Selector Name=\"ShellId\">SHELL-1</w:Selector>"));
        assert!(delete.contains("<s:Body></s:Body>"));
    }

    #[test]
    fn parses_shell_id_from_create_response() {
        assert_eq!(
            parse_shell_id(CREATE_RESPONSE).as_deref(),
            Some("1A2B3C4D-1111-2222-3333-444455556666")
        );
        assert_eq!(parse_shell_id(COMMAND_RESPONSE), None);
        assert_eq!(parse_shell_id(""), None);
        assert_eq!(parse_shell_id("not xml"), None);
    }

    #[test]
    fn parses_command_id() {
        assert_eq!(
            parse_command_id(COMMAND_RESPONSE).as_deref(),
            Some("AAAA-BBBB-CCCC")
        );
        assert_eq!(parse_command_id(CREATE_RESPONSE), None);
    }

    #[test]
    fn parses_receive_streams_and_done_state() {
        let xml = receive_response("Done", Some("0"), "cHJvYmUgb3V0cHV0");
        let outcome = parse_receive_response(&xml).expect("receive outcome");
        assert_eq!(outcome.stdout, b"probe output");
        assert_eq!(outcome.stderr, b"stderr");
        assert_eq!(outcome.state, ReceiveState::Done(0));
    }

    #[test]
    fn parses_nonzero_exit_code() {
        let xml = receive_response("Done", Some("7"), "");
        let outcome = parse_receive_response(&xml).expect("receive outcome");
        assert_eq!(outcome.state, ReceiveState::Done(7));
    }

    #[test]
    fn parses_pending_state_without_exit_code() {
        let xml = receive_response("Pending", None, "cGFydGlhbA==");
        let outcome = parse_receive_response(&xml).expect("receive outcome");
        assert_eq!(outcome.state, ReceiveState::Pending);
        assert_eq!(outcome.stdout, b"partial");
    }

    #[test]
    fn pending_state_may_be_an_empty_element() {
        let xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>\
             <rsp:ReceiveResponse xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">\
             <rsp:CommandState CommandId=\"CMD\" State=\"rsp:Pending\"/>\
             </rsp:ReceiveResponse></s:Body></s:Envelope>";
        let outcome = parse_receive_response(xml).expect("receive outcome");
        assert_eq!(outcome.state, ReceiveState::Pending);
    }

    #[test]
    fn done_without_parsable_exit_code_is_an_error() {
        let xml = receive_response("Done", Some("not-a-number"), "");
        assert!(parse_receive_response(&xml).is_err());
    }

    #[test]
    fn malformed_stream_base64_is_an_error() {
        let xml = receive_response("Done", Some("0"), "!!!not-base64!!!");
        assert!(parse_receive_response(&xml).is_err());
    }

    #[test]
    fn unknown_command_state_is_an_error() {
        let xml = receive_response("Bogus", None, "");
        assert!(parse_receive_response(&xml).is_err());
    }

    #[test]
    fn parses_soap_faults() {
        let xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>\
             <s:Fault><s:Code><s:Value>s:Receiver</s:Value>\
             <s:Subcode><s:Value>a:DestinationUnreachable</s:Value></s:Subcode></s:Code>\
             <s:Reason><s:Text xml:lang=\"en-US\">The WSMan service could not launch\
             the process</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>";
        let fault = parse_soap_fault(xml).expect("fault");
        assert_eq!(fault.code, "s:Receiver");
        assert_eq!(fault.subcode.as_deref(), Some("a:DestinationUnreachable"));
        assert!(fault.reason.contains("WSMan service"));
        assert!(fault.to_string().contains("DestinationUnreachable"));
    }

    #[test]
    fn no_fault_in_success_responses() {
        assert_eq!(parse_soap_fault(CREATE_RESPONSE), None);
        assert_eq!(parse_soap_fault(""), None);
    }

    #[test]
    fn excerpt_collapses_and_truncates() {
        assert_eq!(excerpt("  a\n\tb  c "), "a b c");
        let long = "x".repeat(300);
        assert_eq!(excerpt(&long).len(), 203);
    }

    #[test]
    fn transport_requires_username_and_password() {
        let profile = CredentialProfile::new("Administrator", 5986, None);
        assert!(WinRmTransport::new(profile.clone(), None, false).is_err());
        assert!(WinRmTransport::new(
            CredentialProfile::new("", 5986, None),
            Some("pw".into()),
            false
        )
        .is_err());
        assert!(
            WinRmTransport::new(profile, Some("bad\npassword".into()), false).is_err(),
            "newlines must be rejected (config injection)"
        );
    }

    #[test]
    fn debug_never_leaks_the_password() {
        let transport = WinRmTransport::new(
            CredentialProfile::new("Administrator", 5986, None),
            Some("supersecret".into()),
            false,
        )
        .expect("transport");
        let rendered = format!("{transport:?}");
        assert!(rendered.contains("Administrator"));
        assert!(!rendered.contains("supersecret"));
        assert!(rendered.contains("<redacted>"));
    }
}
