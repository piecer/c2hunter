#!/bin/sh
set -eu

usage() {
  echo "usage: $0 [--binary PATH] [--controller-url URL] [--enrollment-token TOKEN] [--no-setcap]" >&2
  exit 2
}

[ "$(id -u)" -eq 0 ] || { echo "installer must run as root" >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BINARY="$SCRIPT_DIR/c2hunter-sensor"
CONTROLLER_URL=""
ENROLLMENT_TOKEN=""
SETCAP=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || usage; BINARY=$2; shift 2 ;;
    --controller-url) [ "$#" -ge 2 ] || usage; CONTROLLER_URL=$2; shift 2 ;;
    --enrollment-token) [ "$#" -ge 2 ] || usage; ENROLLMENT_TOKEN=$2; shift 2 ;;
    --no-setcap) SETCAP=0; shift ;;
    *) usage ;;
  esac
done
[ -x "$BINARY" ] || { echo "sensor binary not found or executable: $BINARY" >&2; exit 1; }
"$BINARY" --version

if ! getent group c2hunter-sensor >/dev/null 2>&1; then groupadd --system c2hunter-sensor; fi
if ! id c2hunter-sensor >/dev/null 2>&1; then
  useradd --system --gid c2hunter-sensor --home-dir /var/lib/c2hunter-sensor --shell /usr/sbin/nologin c2hunter-sensor
fi
install -d -m 0750 -o root -g c2hunter-sensor /etc/c2hunter-sensor
install -d -m 0700 -o c2hunter-sensor -g c2hunter-sensor /var/lib/c2hunter-sensor/state /var/lib/c2hunter-sensor/spool
install -m 0755 -o root -g root "$BINARY" /usr/local/bin/c2hunter-sensor
install -m 0640 -o root -g c2hunter-sensor "$SCRIPT_DIR/config.yaml" /etc/c2hunter-sensor/config.yaml
install -m 0640 -o root -g c2hunter-sensor "$SCRIPT_DIR/environment" /etc/c2hunter-sensor/environment
install -m 0644 -o root -g root "$SCRIPT_DIR/c2hunter-sensor.service" /etc/systemd/system/c2hunter-sensor.service
if [ -n "$CONTROLLER_URL" ]; then
  sed -i "s|^C2HUNTER_CONTROLLER_URL=.*|C2HUNTER_CONTROLLER_URL=$CONTROLLER_URL|" /etc/c2hunter-sensor/environment
fi
if [ -n "$ENROLLMENT_TOKEN" ]; then
  sed -i "s|^C2HUNTER_ENROLLMENT_TOKEN=.*|C2HUNTER_ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN|" /etc/c2hunter-sensor/environment
fi
if [ "$SETCAP" -eq 1 ]; then
  command -v setcap >/dev/null 2>&1 || { echo "setcap is required (install libcap2-bin/libcap); or use --no-setcap and run with an explicitly privileged unit" >&2; exit 1; }
  setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/c2hunter-sensor
else
  echo "WARNING: capabilities were not installed; AF_PACKET capture will fail unless capabilities are granted by another mechanism" >&2
fi
systemctl daemon-reload
systemctl enable c2hunter-sensor.service
cat <<EOF
Installed c2hunter-sensor. Before starting, verify:
  set -a; . /etc/c2hunter-sensor/environment; set +a
  /usr/local/bin/c2hunter-sensor validate-config /etc/c2hunter-sensor/config.yaml
  /usr/local/bin/c2hunter-sensor interfaces
Then run: systemctl start c2hunter-sensor
The service runs as c2hunter-sensor; only CAP_NET_RAW and CAP_NET_ADMIN are granted via file capabilities.
EOF
