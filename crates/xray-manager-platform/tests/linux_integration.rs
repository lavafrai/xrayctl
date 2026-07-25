#![cfg(target_os = "linux")]

use std::process::Command;

#[test]
#[ignore = "requires systemd tooling on a real Linux host"]
fn systemd_templates_pass_systemd_analyze_verify() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let xray = directory.path().join("xray.service");
    let policy = directory.path().join("xray-tun-policy.service");
    std::fs::write(&xray, xray_manager_platform::templates::xray_service()).expect("xray unit");
    std::fs::write(
        &policy,
        xray_manager_platform::templates::tun_policy_service(),
    )
    .expect("policy unit");
    let status = Command::new("systemd-analyze")
        .arg("verify")
        .arg(&xray)
        .arg(&policy)
        .status()
        .expect("systemd-analyze must be installed");
    assert!(status.success());
}

#[test]
#[ignore = "requires an explicitly prepared EndeavourOS integration host"]
fn required_linux_commands_are_present() {
    for command in ["systemctl", "journalctl", "ip", "nft", "unshare", "mount"] {
        let status = Command::new("sh")
            .args(["-c", &format!("command -v {command}")])
            .status()
            .expect("shell command");
        assert!(status.success(), "missing {command}");
    }
    assert!(std::path::Path::new("/dev/net/tun").exists());
}
