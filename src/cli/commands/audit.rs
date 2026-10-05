//! Handlers for job history and audit trail listing.

use anyhow::Result;

use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::open_store;

pub(crate) async fn jobs(config: &Config, limit: usize, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let jobs = store.list_jobs(Some(limit)).await?;
    print!("{}", orbyn::output::jobs(&jobs, format));
    Ok(())
}

pub(crate) async fn audit(config: &Config, limit: usize, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let events = store.list_audit_events(Some(limit)).await?;
    print!("{}", orbyn::output::audit_events(&events, format));
    Ok(())
}
