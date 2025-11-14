use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let format_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(FmtSpan::CLOSE)
        .json();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(format_layer)
        .init();

    tracing::info!("Logging initialized");
    Ok(())
}

pub fn init_logging_with_level(level: Level) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::new(level.to_string());

    let format_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(FmtSpan::CLOSE)
        .json();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(format_layer)
        .init();

    tracing::info!("Logging initialized with level: {}", level);
    Ok(())
}

#[macro_export]
macro_rules! trace_function {
    ($func_name:expr) => {
        tracing::debug!("Entering function: {}", $func_name);
    };
}

#[macro_export]
macro_rules! audit_log {
    ($action:expr, $subject:expr, $resource:expr) => {
        tracing::warn!(
            action = $action,
            subject = $subject,
            resource = $resource,
            "AUDIT: Action performed"
        );
    };
}