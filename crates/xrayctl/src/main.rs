mod cli;
mod composition;
mod tui;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use cli::{Cli, Command};
use std::io::{self, Read, Write};
use xray_manager_core::application::{Operation, OperationOptions, Query};
use xray_manager_core::config::AppProfile;
use xray_manager_core::routing::RoutingConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli);
    match run(&cli).await {
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
        Err(error) => Err(error),
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
                    Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
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
                        println!("{}", serde_json::to_string_pretty(data)?);
                    } else if !cli.quiet {
                        println!("{} completed", result.operation);
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

fn init_tracing(cli: &Cli) {
    let filter = if cli.verbose {
        "xrayctl=debug,xray_manager_core=debug,xray_manager_platform=debug"
    } else {
        "warn"
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(!cli.no_color)
        .try_init();
}
