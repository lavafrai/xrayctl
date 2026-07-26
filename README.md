# xray-manager

`xrayctl` is a modular, single-binary manager for Xray on Arch Linux and
EndeavourOS. The application core is platform-independent; operating-system
integration is selected through a built-in runtime backend registry.

The project does not run a manager daemon, does not install update timers, and
does not globally route the host through TUN. Only applications explicitly
started through the privileged app runner are marked for TUN routing.

## Development on Windows

The normal development workflow requires neither WSL nor systemd:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --workspace
```

Windows builds exercise parsers, rendering, state transitions, atomic portable
filesystem operations, backend selection and Linux plan/template generation.
Real Windows Service and Windows TUN backends are intentionally not implemented
in the first release. Unsupported operations return `PlatformUnsupported`.

## Linux release

On Arch/EndeavourOS, install the build tools explicitly, then install the pinned
toolchain and musl target:

```bash
sudo pacman -S --needed base-devel rustup musl
rustup toolchain install 1.97.1 --profile minimal
rustup target add --toolchain 1.97.1 x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo +1.97.1 build --release --target x86_64-unknown-linux-musl -p xrayctl
cp target/x86_64-unknown-linux-musl/release/xrayctl xrayctl-linux-x86_64
```

Self-install:

```bash
chmod +x xrayctl-linux-x86_64
./xrayctl-linux-x86_64 --dry-run --json install
sudo ./xrayctl-linux-x86_64 install
```

The install plan performs a non-mutating dependency preflight. It never runs
`pacman` on its own. If Arch packages are missing, install exactly the command
reported by the structured error (normally):

```bash
sudo pacman -S --needed iproute2 nftables
```

Then repeat the install command. When invoked through `sudo`, the installer
validates `SUDO_USER`/`SUDO_UID`/`SUDO_GID` and grants that existing user access
to manager state. Use `--user <login>` only when installing from a root shell
that has no sudo identity.

The installer downloads the current non-prerelease Xray release and configured
geodata over HTTPS, validates a staged candidate, installs and starts the two
systemd units, and persists the backend selection. `--user` grants the named
existing user access to manager state; log out and back in after the first
installation so the new group membership is visible.

Add and activate a subscription:

```bash
sudo xrayctl subscription add main
cat subscription.txt | sudo xrayctl subscription add main --url-stdin
sudo xrayctl subscription refresh main
xrayctl node list
sudo xrayctl node probe-all
sudo xrayctl node select <ID-or-unique-prefix>
xrayctl status
```

The default no-argument command opens the TUI. Probes run concurrently, `/`
filters without reordering rows, `s` explicitly sorts by latency, and Enter
validates and activates the highlighted node. A failed probe or activation is
shown in the status panel and does not close the TUI:

```bash
sudo xrayctl
```

Manager diagnostics are written separately from Xray output, so temporary
probe processes cannot overwrite the TUI. On Linux the persistent manager log
is `/var/log/xray-manager/xrayctl.log`; raw Xray service logs are shown only
when explicitly requested:

```bash
sudo xrayctl --verbose doctor
sudo tail -n 200 /var/log/xray-manager/xrayctl.log
sudo xrayctl service logs --lines 100
```

Use `--log-file <path>` or `XRAY_MANAGER_LOG=<path>` to select another manager
log. `--no-color` disables ANSI colors and `--json` remains machine-readable.

Selective application routing requires an active TUN policy. A command supplied
after `--` does not need a saved profile:

```bash
sudo xrayctl tun enable
sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XAUTHORITY \
  xrayctl app run -- curl https://ifconfig.me
sudo xrayctl app add discord
sudo xrayctl upgrade
sudo xrayctl app run discord
sudo xrayctl app test discord
```

`app test` does not launch the profile command. It uses `curl` as a bounded IP
check inside and outside the profile's GID/mount namespace, clears inherited
proxy variables, and fails unless the direct and TUN IPv4 addresses differ.

Use `--dry-run --json` to inspect a privileged plan without applying it:

```bash
xrayctl --dry-run --json install
```

Useful recovery commands:

```bash
sudo xrayctl doctor
sudo xrayctl repair
sudo xrayctl core rollback
sudo xrayctl asset rollback
sudo xrayctl uninstall       # keeps configuration and state
sudo xrayctl --yes purge     # removes only project-owned resources
```

`repair` reuses validated current core/assets/config generations. A missing or
damaged current artifact is rebuilt through staging; healthy generations are
not shifted into `previous` merely because repair was run.

## Backend selection

Selection precedence is CLI, configuration, installed state, then automatic
detection:

```bash
xrayctl --backend service=systemd --backend firewall=nftables status
```

```toml
[platform]
layout = "auto"
installer = "auto"
service = "auto"
firewall = "auto"
policy_routing = "auto"
tun = "auto"
app_runner = "auto"
mount_isolation = "auto"
desktop_proxy = "auto"
```

See [backend development](docs/backends.md) for the extension contract.

## Protocol compatibility notes

- VLESS/VMess/Trojan transports are rendered to the current Xray schema and
  every candidate configuration is checked by the downloaded Xray binary
  before activation.
- Legacy mKCP `seed` is preserved as a warning but is not activated because
  current Xray removed that field. RAW `headerType=none|http` is rendered
  explicitly.
- Shadowsocks SIP002 is supported without plugins. Known and unknown
  `plugin=` values remain visible with a warning and are refused at activation
  instead of being silently ignored.
- FinalMask `fm` JSON is supported for VLESS and Hysteria2. Legacy
  `fragment=length,delay,tlshello` is mapped to Xray's TCP FinalMask. If a
  Hysteria2 share contains both `fm` and legacy `obfs` aliases, `fm` is
  authoritative so the same Salamander mask is never applied twice.
- Hysteria2 nodes with genuinely unmappable parameters remain visible as
  unsupported. A node is activated only after the candidate passes the real
  `xray run -test`; a failed candidate leaves the active generation unchanged.
- Candidate validation uses a disposable copy without the TUN inbound because
  Xray initializes TUN even in `run -test`. The committed config retains TUN;
  service restart plus the proxied healthcheck validate the real runtime and
  trigger rollback on failure.

## Security boundaries

- Subscription URLs and credentials are absent from DTO and debug output.
- Downloads require HTTPS, enforce time and size limits, and reject downgrade
  redirects.
- Core archives are traversal-checked and candidates must run successfully.
- Assets resembling HTML, XML, or JSON error documents are rejected.
- Configuration/core/assets use current and previous generations with rollback.
- The nftables adapter owns only `table inet xray_manager`; it never flushes the
  global ruleset.
- Policy routing uses a separate table with fail-closed fallback and does not
  replace the main default route.

## Linux verification status

Windows tests cannot validate systemd, nftables, `/dev/net/tun`, mount
namespaces, NetworkManager interaction, or real proxy traffic. Run the guarded
integration harness on a disposable EndeavourOS test host:

```bash
sudo env XRAY_MANAGER_LINUX_INTEGRATION=1 bash scripts/test-linux-integration.sh \
  ./target/x86_64-unknown-linux-musl/release/xrayctl
```

Review the script before enabling it: it installs project-owned system
resources and deliberately leaves them in place for inspection. Remove them
after testing with `sudo xrayctl uninstall`, or use
`sudo xrayctl --yes purge` when the host contained no data you need to keep.
