use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use std::{error::Error, fmt::Write as _};
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::ports::{XrayRunner, XrayTestRequest};
use xray_manager_core::render::render_xray_config;
use xray_manager_core::routing::RoutingConfig;
use xray_manager_core::subscription::parse_subscription;
use xray_manager_platform::portable::ProcessXrayRunner;

#[tokio::test]
#[ignore = "requires an explicit Xray executable and private subscription fixtures"]
async fn every_renderable_private_subscription_node_passes_real_xray_validation() {
    let executable = required_path("XRAY_MANAGER_REAL_XRAY");
    let assets = required_path("XRAY_MANAGER_REAL_XRAY_ASSETS");
    let report_directory = required_path("XRAY_MANAGER_REAL_XRAY_REPORT_DIR");
    let subscriptions = std::env::var_os("XRAY_MANAGER_TEST_SUBSCRIPTIONS")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .filter(|paths| !paths.is_empty())
        .expect("XRAY_MANAGER_TEST_SUBSCRIPTIONS must contain fixture paths");
    std::fs::create_dir_all(&report_directory).expect("report directory");

    // Keep TUN enabled here: ProcessXrayRunner must create a side-effect-free
    // validation copy. This regression test caught Xray's `run -test`
    // attempting to open WinTUN or an already-active Linux xray0 interface.
    let config = ManagerConfig::default();
    let runner = ProcessXrayRunner;
    let routing = RoutingConfig::preset("global-proxy").expect("routing preset");
    let mut rejected = Vec::new();
    let mut rendered = 0usize;
    let mut intentionally_unsupported = 0usize;

    for (subscription_index, path) in subscriptions.iter().enumerate() {
        let bytes = std::fs::read(path).expect("private subscription fixture");
        let parsed = parse_subscription(&bytes, &format!("fixture-{}", subscription_index + 1))
            .expect("subscription should parse");
        for node in parsed.nodes {
            let files = match render_xray_config(&config, Some(&node), &routing, Vec::new()) {
                Ok(files) => files,
                Err(_) => {
                    intentionally_unsupported += 1;
                    continue;
                }
            };
            rendered += 1;
            let directory = tempfile::tempdir().expect("candidate directory");
            for (name, value) in files {
                let bytes = serde_json::to_vec_pretty(&value).expect("candidate JSON");
                std::fs::write(directory.path().join(name), bytes).expect("candidate file");
            }
            let request = XrayTestRequest {
                executable: executable.clone(),
                asset_dir: assets.clone(),
                config_dir: directory.path().to_owned(),
            };
            if let Err(error) = runner.test_config(&request).await {
                let report = report_directory.join(format!("{}.log", node.id.short()));
                std::fs::write(&report, error.to_string()).expect("validation report");
                rejected.push((
                    node.id.short().to_owned(),
                    format!("{:?}", node.protocol).to_ascii_lowercase(),
                    node.transport.kind.clone(),
                    node.extra.keys().cloned().collect::<Vec<_>>(),
                    report,
                ));
            }
        }
    }

    println!(
        "real Xray audit: rendered={rendered}, intentionally_unsupported={intentionally_unsupported}"
    );
    for (id, protocol, transport, query_keys, report) in &rejected {
        println!(
            "rejected node={id} protocol={protocol} transport={transport} query_keys={} report={}",
            query_keys.join(","),
            report.display()
        );
    }
    assert!(rejected.is_empty(), "real Xray rejected rendered nodes");
}

#[tokio::test]
#[ignore = "requires real network access, Xray, and private subscription fixtures"]
async fn every_private_subscription_node_starts_and_proxies_a_healthcheck() {
    let executable = required_path("XRAY_MANAGER_REAL_XRAY");
    let assets = required_path("XRAY_MANAGER_REAL_XRAY_ASSETS");
    let report_directory = required_path("XRAY_MANAGER_REAL_XRAY_REPORT_DIR");
    let subscriptions = private_subscription_paths();
    std::fs::create_dir_all(&report_directory).expect("report directory");

    let routing = RoutingConfig::preset("global-proxy").expect("routing preset");
    let mut failures = Vec::new();
    let mut started = 0usize;
    for (subscription_index, path) in subscriptions.iter().enumerate() {
        let bytes = std::fs::read(path).expect("private subscription fixture");
        let parsed = parse_subscription(&bytes, &format!("fixture-{}", subscription_index + 1))
            .expect("subscription should parse");
        for node in parsed.nodes {
            let mut config = ManagerConfig::default();
            config.tun.enabled = false;
            config.proxy.socks_port = unused_tcp_port();
            config.proxy.http_port = unused_tcp_port();
            let mut files = render_xray_config(&config, Some(&node), &routing, Vec::new())
                .expect("every fixture node should be renderable");
            // Raw Xray diagnostics stay in the private temporary report. They
            // are never inherited by the test/TUI terminal.
            files.get_mut("00_log.json").expect("log config")["log"]["loglevel"] =
                serde_json::json!("debug");
            let directory = tempfile::tempdir().expect("candidate directory");
            for (name, value) in files {
                let bytes = serde_json::to_vec_pretty(&value).expect("candidate JSON");
                std::fs::write(directory.path().join(name), bytes).expect("candidate file");
            }

            let report = report_directory.join(format!("{}-runtime.log", node.id.short()));
            let stdout = std::fs::File::create(&report).expect("runtime report");
            let stderr = stdout.try_clone().expect("clone runtime report");
            let mut child = tokio::process::Command::new(&executable)
                .env("XRAY_LOCATION_ASSET", &assets)
                .args(["run", "-confdir"])
                .arg(directory.path())
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .kill_on_drop(true)
                .spawn()
                .expect("real Xray process");

            let ready = wait_for_listener(&mut child, config.proxy.socks_port).await;
            if let Err(reason) = ready {
                failures.push((
                    node.id.short().to_owned(),
                    format!("{:?}", node.protocol).to_ascii_lowercase(),
                    node.transport.kind.clone(),
                    format!("startup: {reason}"),
                    report,
                ));
                let _ = child.kill().await;
                continue;
            }
            started += 1;

            let proxy =
                reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", config.proxy.socks_port))
                    .expect("SOCKS proxy URL");
            let client = reqwest::Client::builder()
                .proxy(proxy)
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::limited(2))
                .build()
                .expect("healthcheck client");
            let result = client.get(&config.general.healthcheck_url).send().await;
            let healthy = result
                .as_ref()
                .is_ok_and(|response| response.status().is_success());
            if !healthy {
                let reason = result.map_or_else(reqwest_error_chain, |response| {
                    format!("HTTP {}", response.status())
                });
                failures.push((
                    node.id.short().to_owned(),
                    format!("{:?}", node.protocol).to_ascii_lowercase(),
                    node.transport.kind.clone(),
                    format!("healthcheck: {reason}"),
                    report,
                ));
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }

    println!("real Xray runtime audit: started={started}");
    for (id, protocol, transport, reason, report) in &failures {
        println!(
            "failed node={id} protocol={protocol} transport={transport} reason={reason} report={}",
            report.display()
        );
    }
    assert!(failures.is_empty(), "real Xray runtime audit failed");
}

fn reqwest_error_chain(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut output = error.to_string();
    let mut source = error.source();
    while let Some(reason) = source {
        let _ = write!(output, ": {reason}");
        source = reason.source();
    }
    output.truncate(512);
    output
}

fn private_subscription_paths() -> Vec<PathBuf> {
    std::env::var_os("XRAY_MANAGER_TEST_SUBSCRIPTIONS")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .filter(|paths| !paths.is_empty())
        .expect("XRAY_MANAGER_TEST_SUBSCRIPTIONS must contain fixture paths")
}

fn unused_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("ephemeral listener")
        .local_addr()
        .expect("ephemeral address")
        .port()
}

async fn wait_for_listener(child: &mut tokio::process::Child, port: u16) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!("Xray exited with {status}"));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("SOCKS listener did not become ready".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| panic!("{name} is required"))
}
