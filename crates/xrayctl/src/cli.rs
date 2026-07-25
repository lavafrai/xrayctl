use anyhow::bail;
use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;
use xray_manager_core::application::Operation;
use xray_manager_core::application::Query;

#[derive(Debug, Parser)]
#[command(name = "xrayctl", version, about = "Modular Xray manager")]
pub struct Cli {
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub quiet: bool,
    #[arg(long, global = true)]
    pub verbose: bool,
    #[arg(long, global = true)]
    pub dry_run: bool,
    #[arg(long, global = true)]
    pub yes: bool,
    #[arg(long, global = true)]
    pub no_color: bool,
    #[arg(long, global = true, value_name = "CAPABILITY=ID")]
    pub backend: Vec<String>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Install {
        #[arg(long)]
        user: Option<String>,
    },
    Repair,
    Uninstall,
    Purge,
    Status,
    Doctor {
        #[arg(long)]
        quick: bool,
    },
    Apply,
    Upgrade {
        #[command(subcommand)]
        target: Option<UpgradeCommand>,
    },
    Subscription {
        #[command(subcommand)]
        command: SubscriptionCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Routing {
        #[command(subcommand)]
        command: RoutingCommand,
    },
    Asset {
        #[command(subcommand)]
        command: AssetCommand,
    },
    Core {
        #[command(subcommand)]
        command: CoreCommand,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    Tun {
        #[command(subcommand)]
        command: TunCommand,
    },
    App {
        #[command(subcommand)]
        command: AppCommand,
    },
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
    #[command(hide = true)]
    Internal {
        #[command(subcommand)]
        command: InternalCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum UpgradeCommand {
    All,
    Core,
    Assets,
    Manager,
}

#[derive(Debug, Subcommand)]
pub enum SubscriptionCommand {
    Add {
        name: String,
        #[arg(long)]
        url_stdin: bool,
    },
    Remove {
        name: String,
    },
    List,
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
    Refresh {
        name: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    List,
    Menu,
    Current,
    Select { id: String },
    Probe { id: String },
    ProbeAll,
}

#[derive(Debug, Subcommand)]
pub enum RoutingCommand {
    Show,
    Edit,
    Validate,
    Apply,
    Preset {
        #[command(subcommand)]
        command: PresetCommand,
    },
    Explain {
        name: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PresetCommand {
    List,
    Apply { name: String },
}

#[derive(Debug, Subcommand)]
pub enum AssetCommand {
    List,
    Show { id: String },
    Rollback,
}

#[derive(Debug, Subcommand)]
pub enum CoreCommand {
    Status,
    List,
    Rollback,
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    Start,
    Stop,
    Restart,
    Status,
    Logs {
        #[arg(long, default_value_t = 100)]
        lines: usize,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    Show,
    Test,
    Env,
    EnableKde {
        #[arg(long)]
        user: String,
    },
    DisableKde {
        #[arg(long)]
        user: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TunCommand {
    Status,
    Enable,
    Disable,
    Test,
    ShowRules,
    Cleanup,
}

#[derive(Debug, Subcommand)]
pub enum AppCommand {
    List,
    Add {
        name: String,
    },
    Edit {
        name: String,
    },
    Remove {
        name: String,
    },
    Run {
        profile: Option<String>,
        #[arg(last = true)]
        command: Vec<String>,
    },
    Test {
        name: String,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum InternalCommand {
    #[command(name = "tun-policy-up")]
    PolicyUp,
    #[command(name = "tun-policy-down")]
    PolicyDown,
    #[command(name = "tun-attach")]
    Attach,
    #[command(name = "tun-detach")]
    Detach,
    #[command(name = "app-enter")]
    AppEnter {
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        gid: u32,
        #[arg(long)]
        tun_gid: u32,
        #[arg(long)]
        user: String,
        #[arg(long)]
        home: PathBuf,
        #[arg(long = "supplementary-gid")]
        supplementary_gids: Vec<u32>,
        #[arg(long)]
        override_dns: bool,
        #[arg(long)]
        clear_proxy_environment: bool,
        #[arg(long)]
        working_directory: Option<PathBuf>,
        #[arg(long = "env")]
        environment: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

pub fn to_operation(command: &Command) -> anyhow::Result<Operation> {
    let operation = match command {
        Command::Install { user } => Operation::Install { user: user.clone() },
        Command::Repair => Operation::Repair,
        Command::Uninstall => Operation::Uninstall,
        Command::Purge => Operation::Purge,
        Command::Apply => Operation::Apply,
        Command::Upgrade { target } => match target {
            None | Some(UpgradeCommand::All) => Operation::UpgradeAll,
            Some(UpgradeCommand::Core) => Operation::UpgradeCore,
            Some(UpgradeCommand::Assets) => Operation::UpgradeAssets,
            Some(UpgradeCommand::Manager) => Operation::UpgradeManager,
        },
        Command::Subscription {
            command: SubscriptionCommand::Refresh { name },
        } => Operation::SubscriptionRefresh { name: name.clone() },
        Command::Subscription {
            command: SubscriptionCommand::Remove { name },
        } => Operation::SubscriptionRemove { name: name.clone() },
        Command::Subscription {
            command: SubscriptionCommand::Enable { name },
        } => Operation::SubscriptionEnable {
            name: name.clone(),
            enabled: true,
        },
        Command::Subscription {
            command: SubscriptionCommand::Disable { name },
        } => Operation::SubscriptionEnable {
            name: name.clone(),
            enabled: false,
        },
        Command::Node {
            command: NodeCommand::Select { id },
        } => Operation::NodeSelect { id: id.clone() },
        Command::Routing {
            command: RoutingCommand::Apply,
        } => Operation::RoutingApply,
        Command::Routing {
            command:
                RoutingCommand::Preset {
                    command: PresetCommand::Apply { name },
                },
        } => Operation::RoutingPreset { name: name.clone() },
        Command::Asset {
            command: AssetCommand::Rollback,
        } => Operation::AssetRollback,
        Command::Core {
            command: CoreCommand::Rollback,
        } => Operation::CoreRollback,
        Command::Service {
            command: ServiceCommand::Start,
        } => Operation::ServiceStart,
        Command::Service {
            command: ServiceCommand::Stop,
        } => Operation::ServiceStop,
        Command::Service {
            command: ServiceCommand::Restart,
        } => Operation::ServiceRestart,
        Command::Tun {
            command: TunCommand::Enable,
        } => Operation::TunEnable,
        Command::Tun {
            command: TunCommand::Disable,
        } => Operation::TunDisable,
        Command::Tun {
            command: TunCommand::Cleanup,
        } => Operation::TunCleanup,
        Command::Proxy {
            command: ProxyCommand::EnableKde { user },
        } => Operation::DesktopProxyEnable { user: user.clone() },
        Command::Proxy {
            command: ProxyCommand::DisableKde { user },
        } => Operation::DesktopProxyDisable { user: user.clone() },
        Command::App {
            command: AppCommand::Run { profile, command },
        } => Operation::AppRun {
            profile: profile.clone(),
            command: command.clone(),
        },
        Command::App {
            command: AppCommand::Test { name },
        } => Operation::AppTest {
            profile: name.clone(),
        },
        Command::App {
            command: AppCommand::Remove { name },
        } => Operation::AppProfileRemove { name: name.clone() },
        Command::Status | Command::Doctor { .. } => {
            bail!("read-only query dispatch is not yet available through this adapter")
        }
        Command::Completion { .. } => bail!("completion is handled directly"),
        Command::Routing {
            command: RoutingCommand::Edit,
        }
        | Command::App {
            command: AppCommand::Add { .. } | AppCommand::Edit { .. },
        } => bail!("this command requires an interactive editor and cannot run in this build"),
        _ => bail!("command is parsed but its application operation is not implemented yet"),
    };
    Ok(operation)
}

pub fn to_query(command: &Command) -> Option<Query> {
    match command {
        Command::Status => Some(Query::Status),
        Command::Doctor { quick } => Some(Query::Doctor { quick: *quick }),
        Command::Node {
            command: NodeCommand::List,
        } => Some(Query::Nodes),
        Command::Subscription {
            command: SubscriptionCommand::List,
        } => Some(Query::Subscriptions),
        Command::Node {
            command: NodeCommand::Current,
        } => Some(Query::CurrentNode),
        Command::Routing {
            command: RoutingCommand::Show,
        } => Some(Query::Routing),
        Command::Routing {
            command: RoutingCommand::Validate,
        } => Some(Query::RoutingValidate),
        Command::Routing {
            command:
                RoutingCommand::Preset {
                    command: PresetCommand::List,
                },
        } => Some(Query::RoutingPresets),
        Command::Asset {
            command: AssetCommand::List,
        } => Some(Query::Assets),
        Command::Core {
            command: CoreCommand::Status,
        } => Some(Query::Core),
        Command::Service {
            command: ServiceCommand::Logs { lines },
        } => Some(Query::ServiceLogs { lines: *lines }),
        Command::Service {
            command: ServiceCommand::Status,
        } => Some(Query::ServiceStatus),
        Command::Proxy {
            command: ProxyCommand::Show,
        } => Some(Query::ProxyShow),
        Command::Proxy {
            command: ProxyCommand::Env,
        } => Some(Query::ProxyEnv),
        Command::Tun {
            command: TunCommand::Status,
        } => Some(Query::TunStatus),
        Command::Tun {
            command: TunCommand::Test,
        } => Some(Query::TunTest),
        Command::Tun {
            command: TunCommand::ShowRules,
        } => Some(Query::TunShowRules),
        Command::Node {
            command: NodeCommand::Probe { id },
        } => Some(Query::NodeProbe { id: id.clone() }),
        Command::Node {
            command: NodeCommand::ProbeAll,
        } => Some(Query::NodeProbeAll),
        Command::Routing {
            command: RoutingCommand::Explain { name },
        } => Some(Query::RoutingExplain { name: name.clone() }),
        Command::Asset {
            command: AssetCommand::Show { id },
        } => Some(Query::AssetShow { id: id.clone() }),
        Command::Core {
            command: CoreCommand::List,
        } => Some(Query::CoreList),
        Command::Proxy {
            command: ProxyCommand::Test,
        } => Some(Query::ProxyTest),
        Command::App {
            command: AppCommand::List,
        } => Some(Query::AppList),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn upgrade_without_target_means_all() {
        let cli = Cli::try_parse_from(["xrayctl", "upgrade"]).expect("CLI should parse");
        let operation = to_operation(cli.command.as_ref().expect("command")).expect("operation");
        assert!(matches!(operation, Operation::UpgradeAll));
    }

    #[test]
    fn backend_override_is_repeatable() {
        let cli = Cli::try_parse_from([
            "xrayctl",
            "--backend",
            "service=systemd",
            "--backend",
            "firewall=nftables",
            "status",
        ])
        .expect("CLI should parse");
        assert_eq!(cli.backend.len(), 2);
    }

    #[test]
    fn app_test_dispatches_a_route_test_without_launching_the_profile() {
        let cli =
            Cli::try_parse_from(["xrayctl", "app", "test", "discord"]).expect("CLI should parse");
        let operation = to_operation(cli.command.as_ref().expect("command")).expect("operation");
        assert!(matches!(
            operation,
            Operation::AppTest { profile } if profile == "discord"
        ));
    }
}
