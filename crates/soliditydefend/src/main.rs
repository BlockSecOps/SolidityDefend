use anyhow::Result;
use cli::CliApp;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    // Initialize tracing/logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "soliditydefend=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Run the CLI application
    let app = CliApp::new();
    app.run()
}
