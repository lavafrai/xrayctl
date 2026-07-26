#!/usr/bin/env bash
set -euo pipefail

if [[ "${XRAY_MANAGER_LINUX_INTEGRATION:-}" != "1" ]]; then
  echo "Refusing to mutate the host. Set XRAY_MANAGER_LINUX_INTEGRATION=1 after reviewing this script." >&2
  exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this integration harness as root." >&2
  exit 2
fi

binary="${1:-}"
if [[ -z "$binary" || ! -x "$binary" ]]; then
  echo "Usage: sudo env XRAY_MANAGER_LINUX_INTEGRATION=1 bash $0 /path/to/xrayctl" >&2
  exit 2
fi

case "$(readlink -f "$binary")" in
  /|/usr|/etc|/var|/opt) echo "Unsafe binary path" >&2; exit 2 ;;
esac

echo "Platform preflight"
test "$(uname -s)" = Linux
command -v systemctl
command -v journalctl
command -v ip
command -v nft
systemctl is-active --quiet NetworkManager

echo "Self install plan"
"$binary" --dry-run --json install

echo "Install"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  "$binary" install --user "$SUDO_USER"
else
  "$binary" install
fi

echo "Static invariants"
test -x /usr/local/bin/xrayctl
systemctl cat xray.service
systemctl cat xray-tun-policy.service
systemd-analyze verify /etc/systemd/system/xray.service \
  /etc/systemd/system/xray-tun-policy.service
systemctl is-enabled --quiet xray.service
systemctl is-active --quiet xray.service
systemctl is-enabled --quiet xray-tun-policy.service
systemctl is-active --quiet xray-tun-policy.service
! systemctl list-timers --all | grep -q xray
nft list table inet xray_manager
ip rule show | grep -q 'lookup 166'
ip route show table 166 | grep -q blackhole
ip -6 route show table 166 | grep -q unreachable
test "$(stat -c '%a:%U:%G' /etc/xray-manager/config.toml)" = "640:root:xray-manager"
test "$(stat -c '%a:%U:%G' /etc/xray-manager/subscriptions.d)" = "700:root:root"
test "$(stat -c '%a:%U:%G' /var/log/xray-manager)" = "2750:root:xray-manager"
systemctl is-active --quiet NetworkManager

echo "Diagnostics"
/usr/local/bin/xrayctl doctor

echo "The subscription, live proxy, selective application, crash/fail-closed,"
echo "rollback, uninstall and purge checks require test credentials and explicit"
echo "operator confirmation; follow README.md and record each result separately."
