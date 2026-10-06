//! Handlers for `orbyn applications`. Translation from the parsed CLI
//! arguments into the application requests lives here; the workflows
//! themselves are in `app::applications`.

use anyhow::Result;

use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::open_store;
use crate::cli::args::ApplicationsAction;

/// Handle `orbyn applications [action]`.
pub(crate) async fn applications(
    config: &Config,
    action: Option<ApplicationsAction>,
) -> Result<()> {
    let store = open_store(config).await?;
    let action = action.unwrap_or(ApplicationsAction::List {
        format: Format::Table,
    });
    match action {
        ApplicationsAction::Discover { format } => {
            let summaries = crate::app::applications::discover(store.as_ref()).await?;
            print!("{}", orbyn::output::applications(&summaries, format));
        }
        ApplicationsAction::List { format } => {
            let summaries = crate::app::applications::list(store.as_ref()).await?;
            print!("{}", orbyn::output::applications(&summaries, format));
        }
        ApplicationsAction::Show {
            application,
            format,
        } => {
            let detail = crate::app::applications::show(store.as_ref(), &application).await?;
            let assets = store.list_assets().await?;
            print!(
                "{}",
                orbyn::output::application_detail(&detail, &assets, format)
            );
        }
        ApplicationsAction::Explain {
            application,
            format,
        } => {
            let detail = crate::app::applications::show(store.as_ref(), &application).await?;
            let assets = store.list_assets().await?;
            print!(
                "{}",
                orbyn::output::application_explain(&detail, &assets, format)
            );
        }
        ApplicationsAction::Create { name } => {
            crate::app::applications::create(store.as_ref(), name).await?
        }
        ApplicationsAction::Add { application, asset } => {
            crate::app::applications::add(store.as_ref(), application, asset).await?
        }
        ApplicationsAction::Remove { application, asset } => {
            crate::app::applications::remove(store.as_ref(), application, asset).await?
        }
    }
    Ok(())
}
