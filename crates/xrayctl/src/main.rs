mod cli;
mod composition;
mod tui;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use cli::{Cli, Command};
use crossterm::style::Stylize;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use xray_manager_core::application::{Operation, OperationOptions, Query};
use xray_manager_core::config::AppProfile;
use xray_manager_core::routing::RoutingConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let tui = uses_tui(&cli);
    init_tracing(&cli, tui);
    let command = cli.command.as_ref().map_or("tui", command_name);
    tracing::debug!(command, tui, "xrayctl invocation started");
    let outcome = run(&cli).await;
    match &outcome {
        Ok(()) => tracing::debug!(command, "xrayctl invocation finished"),
        Err(error) => tracing::debug!(
            command,
            code = error
                .downcast_ref::<xray_manager_core::ManagerError>()
                .map_or("operation_failed", |error| error.code()),
            "xrayctl invocation failed"
        ),
    }
    match outcome {
        Ok(()) => Ok(()),
        Err(error) if cli.json => {
            let manager_error = error.downcast_ref::<xray_manager_core::ManagerError>();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": manager_error.map_or("operation_failed", |error| error.code()),
                        "message": error.to_string(),
                        "details": manager_error.map_or_else(
                            || serde_json::json!({}),
                            xray_manager_core::ManagerError::details
                        )
                    }
                }))?
            );
            std::process::exit(1);
        }
        Err(error) => {
            print_human_error(&cli, &error);
            std::process::exit(1);
        }
    }
}

async fn run(cli: &Cli) -> anyhow::Result<()> {
    if let Some(Command::Internal { command }) = &cli.command {
        return run_internal(cli, command.clone()).await;
    }
    let service = composition::compose(cli).await?;
    let Some(command) = cli.command.as_ref() else {
        return tui::run(service).await.context("TUI failed");
    };
    match command {
        Command::Completion { shell } => {
            let mut command = Cli::command();
            clap_complete::generate(*shell, &mut command, "xrayctl", &mut io::stdout());
        }
        command => {
            if matches!(
                command,
                Command::Node {
                    command: cli::NodeCommand::Menu
                }
            ) {
                return tui::run(service).await.context("TUI failed");
            }
            if let Some(query) = cli::to_query(command) {
                let shell_environment =
                    matches!(query, xray_manager_core::application::Query::ProxyEnv) && !cli.json;
                let result = service.query(query).await;
                match result {
                    Ok(value) if cli.json => println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"ok": true, "data": value, "warnings": []})
                        )?
                    ),
                    Ok(value) if shell_environment => {
                        let object = value
                            .as_object()
                            .context("proxy environment response is not an object")?;
                        for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
                            if let Some(value) = object.get(key).and_then(|value| value.as_str()) {
                                println!("export {key}={value}");
                            }
                        }
                    }
                    Ok(value) => print_query_result(cli, command, &value)?,
                    Err(error) if cli.json => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": {
                                    "code": error.code(),
                                    "message": error.to_string(),
                                    "details": error.details()
                                }
                            }))?
                        );
                        std::process::exit(1);
                    }
                    Err(error) => return Err(anyhow::Error::new(error)),
                }
                return Ok(());
            }
            let operation = match command {
                Command::Subscription {
                    command: cli::SubscriptionCommand::Add { name, url_stdin },
                } => {
                    let url = if *url_stdin {
                        let mut value = String::new();
                        io::stdin()
                            .read_to_string(&mut value)
                            .context("failed to read subscription URL from stdin")?;
                        value.trim().to_owned()
                    } else {
                        rpassword::prompt_password("Subscription URL: ")
                            .context("failed to read subscription URL")?
                    };
                    xray_manager_core::application::Operation::SubscriptionAdd {
                        name: name.clone(),
                        url,
                    }
                }
                Command::App {
                    command: cli::AppCommand::Add { name },
                } => edit_app_profile(&service, name, false).await?,
                Command::App {
                    command: cli::AppCommand::Edit { name },
                } => edit_app_profile(&service, name, true).await?,
                Command::Routing {
                    command: cli::RoutingCommand::Edit,
                } => edit_routing(&service).await?,
                _ => match cli::to_operation(command) {
                    Ok(operation) => operation,
                    Err(error) if cli.json => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": {
                                    "code": "command_not_implemented",
                                    "message": error.to_string(),
                                    "details": {}
                                }
                            }))?
                        );
                        std::process::exit(1);
                    }
                    Err(error) => return Err(error),
                },
            };
            #[cfg(target_os = "linux")]
            let operation = {
                let mut operation = operation;
                if let Operation::Install { user } = &mut operation
                    && user.is_none()
                {
                    *user = xray_manager_platform::linux::invoking_user()?;
                }
                operation
            };
            if matches!(command, Command::Purge) && !cli.yes && !cli.dry_run {
                anyhow::bail!("purge requires explicit confirmation with --yes");
            }
            #[cfg(target_os = "linux")]
            if !cli.dry_run && !service.is_elevated().await? {
                return Err(anyhow::Error::new(
                    xray_manager_core::ManagerError::PrivilegeRequired,
                ));
            }
            let result = service
                .execute(
                    operation,
                    OperationOptions {
                        dry_run: cli.dry_run,
                        assume_yes: cli.yes,
                    },
                )
                .await;
            match result {
                Ok(result) if cli.json => {
                    let warnings = result.warnings.clone();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "data": result,
                            "warnings": warnings
                        }))?
                    );
                }
                Ok(result) => {
                    if let Some(plan) = &result.plan {
                        println!("{}", serde_json::to_string_pretty(&plan)?);
                    } else if let Some(data) = &result.data {
                        print_json(data)?;
                    } else if !cli.quiet {
                        print_operation_success(cli, &result.operation);
                    }
                }
                Err(error) if cli.json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": {
                                "code": error.code(),
                                "message": error.to_string(),
                                "details": error.details()
                            }
                        }))?
                    );
                    std::process::exit(1);
                }
                Err(error) => return Err(anyhow::Error::new(error)),
            }
        }
    }
    Ok(())
}

async fn edit_app_profile(
    service: &xray_manager_core::ManagerService,
    name: &str,
    existing: bool,
) -> anyhow::Result<Operation> {
    let profile = if existing {
        let profiles = service.query(Query::AppList).await?;
        profiles
            .as_array()
            .into_iter()
            .flatten()
            .find(|profile| profile.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .cloned()
            .with_context(|| format!("app profile '{name}' was not found"))
            .and_then(|value| serde_json::from_value(value).context("invalid app profile"))?
    } else {
        AppProfile {
            name: name.into(),
            command: vec!["/usr/bin/example".into()],
            clear_proxy_environment: true,
            override_dns: true,
            working_directory: None,
            environment: Default::default(),
        }
    };
    let encoded = toml::to_string_pretty(&profile).context("failed to encode app profile")?;
    let edited = edit_toml(&encoded)?;
    let profile = AppProfile::parse(&edited).map_err(anyhow::Error::new)?;
    if profile.name != name {
        anyhow::bail!("edited profile name must remain '{name}'");
    }
    Ok(Operation::AppProfilePut { profile })
}

async fn edit_routing(service: &xray_manager_core::ManagerService) -> anyhow::Result<Operation> {
    let value = service.query(Query::Routing).await?;
    let routing: RoutingConfig = serde_json::from_value(
        value
            .get("routing")
            .cloned()
            .context("routing query has no routing value")?,
    )
    .context("invalid routing response")?;
    let encoded = toml::to_string_pretty(&routing).context("failed to encode routing")?;
    let edited = edit_toml(&encoded)?;
    let routing = RoutingConfig::parse(&edited).map_err(anyhow::Error::new)?;
    Ok(Operation::RoutingSet { routing })
}

fn edit_toml(initial: &str) -> anyhow::Result<String> {
    let mut file = tempfile::Builder::new()
        .suffix(".toml")
        .tempfile()
        .context("failed to create editor file")?;
    file.write_all(initial.as_bytes())
        .and_then(|()| file.flush())
        .context("failed to prepare editor file")?;
    let editor = std::env::var("SUDO_EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "vi".into()
            }
        });
    let status = std::process::Command::new(&editor)
        .arg(file.path())
        .status()
        .with_context(|| format!("failed to launch editor '{editor}'"))?;
    if !status.success() {
        anyhow::bail!("editor exited with {status}");
    }
    std::fs::read_to_string(file.path()).context("failed to read edited file")
}

#[cfg(target_os = "linux")]
async fn run_internal(cli: &Cli, command: cli::InternalCommand) -> anyhow::Result<()> {
    use xray_manager_platform::linux::{
        AppNamespaceRequest, TunInternalAction, enter_app_namespace, run_tun_internal,
    };
    let config = composition::load_config(cli).await?;
    match command {
        cli::InternalCommand::PolicyUp => {
            run_tun_internal(TunInternalAction::PolicyUp, &config).await
        }
        cli::InternalCommand::PolicyDown => {
            run_tun_internal(TunInternalAction::PolicyDown, &config).await
        }
        cli::InternalCommand::Attach => run_tun_internal(TunInternalAction::Attach, &config).await,
        cli::InternalCommand::Detach => run_tun_internal(TunInternalAction::Detach, &config).await,
        cli::InternalCommand::AppEnter {
            uid,
            gid,
            tun_gid,
            user,
            home,
            supplementary_gids,
            override_dns,
            clear_proxy_environment,
            working_directory,
            environment,
            command,
        } => enter_app_namespace(
            AppNamespaceRequest {
                uid,
                gid,
                tun_gid,
                user,
                home,
                supplementary_gids,
                override_dns,
                clear_proxy_environment,
                working_directory,
                environment,
                command,
            },
            &config,
        ),
    }
    .map_err(anyhow::Error::new)
}

#[cfg(not(target_os = "linux"))]
async fn run_internal(_cli: &Cli, _command: cli::InternalCommand) -> anyhow::Result<()> {
    Err(anyhow::Error::new(
        xray_manager_core::ManagerError::PlatformUnsupported {
            capability: xray_manager_core::ports::Capability::Tun,
            platform: std::env::consts::OS.into(),
            backend: None,
            reason: "TUN policy commands are Linux-only".into(),
            recommendation: Some("run this internal command on Linux".into()),
        },
    ))
}

fn uses_tui(cli: &Cli) -> bool {
    cli.command.is_none()
        || matches!(
            cli.command,
            Some(Command::Node {
                command: cli::NodeCommand::Menu
            })
        )
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Install { .. } => "install",
        Command::Repair => "repair",
        Command::Uninstall => "uninstall",
        Command::Purge => "purge",
        Command::Status => "status",
        Command::Doctor { .. } => "doctor",
        Command::Apply => "apply",
        Command::Upgrade { .. } => "upgrade",
        Command::Subscription { .. } => "subscription",
        Command::Node { .. } => "node",
        Command::Routing { .. } => "routing",
        Command::Asset { .. } => "asset",
        Command::Core { .. } => "core",
        Command::Service { .. } => "service",
        Command::Proxy { .. } => "proxy",
        Command::Tun { .. } => "tun",
        Command::App { .. } => "app",
        Command::Completion { .. } => "completion",
        Command::Internal { .. } => "internal",
    }
}

fn init_tracing(cli: &Cli, tui: bool) {
    let file_layer = manager_log_writer(cli).map(|writer| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(writer)
            .with_filter(EnvFilter::new(
                "xrayctl=debug,xray_manager_core=debug,xray_manager_platform=debug",
            ))
    });
    let stderr_layer = (!tui).then(|| {
        let filter = if cli.verbose {
            "xrayctl=debug,xray_manager_core=debug,xray_manager_platform=debug"
        } else {
            "warn"
        };
        tracing_subscriber::fmt::layer()
            .with_ansi(color_enabled(cli))
            .with_target(cli.verbose)
            .with_writer(io::stderr)
            .with_filter(EnvFilter::new(filter))
    });
    let _ = tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer)
        .try_init();
}

fn manager_log_writer(cli: &Cli) -> Option<SharedLogWriter> {
    let explicit = cli
        .log_file
        .clone()
        .or_else(|| std::env::var_os("XRAY_MANAGER_LOG").map(PathBuf::from));
    let path = explicit.clone().unwrap_or_else(default_manager_log_path);
    let parent = path.parent()?;
    if explicit.is_some() || !cfg!(target_os = "linux") {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("could not create manager log directory: {error}");
            return None;
        }
    } else if !parent.is_dir() {
        return None;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o640);
    }
    match options.open(&path) {
        Ok(file) => Some(SharedLogWriter(Arc::new(Mutex::new(file)))),
        Err(error) => {
            if cli.verbose {
                eprintln!("could not open manager log {}: {error}", path.display());
            }
            None
        }
    }
}

fn default_manager_log_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/log/xray-manager/xrayctl.log")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".xray-manager/logs/xrayctl.log")
    }
}

#[derive(Clone)]
struct SharedLogWriter(Arc<Mutex<File>>);

struct SharedLogGuard(Arc<Mutex<File>>);

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = SharedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogGuard(Arc::clone(&self.0))
    }
}

impl Write for SharedLogGuard {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("manager log lock was poisoned"))?
            .write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("manager log lock was poisoned"))?
            .flush()
    }
}

fn color_enabled(cli: &Cli) -> bool {
    !cli.no_color && io::stdout().is_terminal()
}

fn print_human_error(cli: &Cli, error: &anyhow::Error) {
    let manager_error = error.downcast_ref::<xray_manager_core::ManagerError>();
    if color_enabled(cli) {
        eprintln!(
            "{} {}",
            "✗".red().bold(),
            manager_error
                .map_or("operation_failed", |error| error.code())
                .red()
        );
    } else {
        eprintln!(
            "ERROR [{}]",
            manager_error.map_or("operation_failed", |error| error.code())
        );
    }
    eprintln!("{error}");
    if let Some(manager_error) = manager_error {
        let details = manager_error.details();
        if let Some(recommendation) = details
            .get("recommendation")
            .and_then(serde_json::Value::as_str)
        {
            eprintln!("Recommendation: {recommendation}");
        }
        if cli.verbose
            && details
                .as_object()
                .is_some_and(|details| !details.is_empty())
        {
            eprintln!(
                "Details: {}",
                serde_json::to_string_pretty(&details).unwrap_or_else(|_| "{}".into())
            );
        }
    }
    let path = cli
        .log_file
        .clone()
        .unwrap_or_else(default_manager_log_path);
    if path.is_file() {
        eprintln!("Manager log: {}", path.display());
    }
}

fn print_operation_success(cli: &Cli, operation: &str) {
    if color_enabled(cli) {
        println!("{} {operation} completed", "✓".green().bold());
    } else {
        println!("OK: {operation} completed");
    }
}

fn print_query_result(
    cli: &Cli,
    command: &Command,
    value: &serde_json::Value,
) -> anyhow::Result<()> {
    match command {
        Command::Node {
            command: cli::NodeCommand::List,
        } => print_node_list(cli, value),
        Command::Node {
            command: cli::NodeCommand::Current,
        } => print_current_node(cli, value),
        Command::Doctor { .. } => print_doctor(cli, value),
        Command::Status => print_status(cli, value),
        _ => print_json(value)?,
    }
    Ok(())
}

fn print_node_list(cli: &Cli, value: &serde_json::Value) {
    let Some(nodes) = value.as_array() else {
        let _ = print_json(value);
        return;
    };
    if nodes.is_empty() {
        println!("No nodes loaded.");
        return;
    }
    for node in nodes {
        let support = node
            .get("support")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let badge = match support {
            "supported" => "SUPPORTED",
            "partial" => "PARTIAL",
            _ => "UNSUPPORTED",
        };
        if color_enabled(cli) {
            match support {
                "supported" => print!("{}", format!("[{badge}]").green()),
                "partial" => print!("{}", format!("[{badge}]").yellow()),
                _ => print!("{}", format!("[{badge}]").red()),
            }
        } else {
            print!("[{badge}]");
        }
        println!(
            " {}  {}  {}",
            json_string(node, "id"),
            json_string(node, "protocol"),
            json_string(node, "name")
        );
        println!(
            "  {}  subscription={}",
            json_string(node, "endpoint"),
            json_string(node, "subscription")
        );
        if let Some(warnings) = node.get("warnings").and_then(serde_json::Value::as_array) {
            for warning in warnings.iter().filter_map(serde_json::Value::as_str) {
                if color_enabled(cli) {
                    println!("  {} {}", "!".yellow(), warning.yellow());
                } else {
                    println!("  WARNING: {warning}");
                }
            }
        }
    }
}

fn print_current_node(cli: &Cli, value: &serde_json::Value) {
    match value
        .get("selected_node")
        .and_then(serde_json::Value::as_str)
    {
        Some(node) if color_enabled(cli) => println!("{} Active node: {node}", "✓".green()),
        Some(node) => println!("Active node: {node}"),
        None if color_enabled(cli) => println!("{} No node is selected", "!".yellow()),
        None => println!("No node is selected"),
    }
}

fn print_doctor(cli: &Cli, value: &serde_json::Value) {
    let Some(checks) = value.get("checks").and_then(serde_json::Value::as_array) else {
        let _ = print_json(value);
        return;
    };
    for check in checks {
        let status = json_string(check, "status");
        let marker = match status.as_str() {
            "PASS" => "✓",
            "WARN" => "!",
            _ => "✗",
        };
        if color_enabled(cli) {
            match status.as_str() {
                "PASS" => print!("{}", marker.green()),
                "WARN" => print!("{}", marker.yellow()),
                _ => print!("{}", marker.red()),
            }
        } else {
            print!("[{status}]");
        }
        println!(
            " {}: {}",
            json_string(check, "id"),
            json_string(check, "message")
        );
        if let Some(remediation) = check.get("remediation").and_then(serde_json::Value::as_str) {
            println!("  Remediation: {remediation}");
        }
    }
}

fn print_status(cli: &Cli, value: &serde_json::Value) {
    let installed = value
        .get("installed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if color_enabled(cli) {
        if installed {
            println!("{} Installed", "✓".green().bold());
        } else {
            println!("{} Not installed", "!".yellow().bold());
        }
    } else {
        println!("Installed: {installed}");
    }
    println!(
        "Selected node: {}",
        value
            .get("selected_node")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("none")
    );
    println!(
        "Xray core: {}",
        value
            .get("core_version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
    );
    if let Some(backends) = value.get("backends").and_then(serde_json::Value::as_array) {
        println!("Backends:");
        for backend in backends {
            println!(
                "  {} = {}",
                json_string(backend, "capability"),
                json_string(backend, "backend_id")
            );
        }
    }
}

fn json_string(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-")
        .to_owned()
}

fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
