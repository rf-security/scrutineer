#!/usr/bin/env bash
#
# install.sh — one-time / idempotent host setup for scrutineer + sharing.
#
# Creates the `scrutineer` service account, prepares /opt/scrutineer (and
# bin/), installs both systemd units, and enables them. Re-run safely on every
# deploy (update.sh calls it) so unit changes roll out.
#
#   sudo ./deploy/install.sh
#
set -euo pipefail

APP_USER=scrutineer
APP_GROUP=scrutineer
APP_DIR=/opt/scrutineer
UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must run as root (use sudo)" >&2
  exit 1
fi

# --- service account -------------------------------------------------------
if ! getent group "$APP_GROUP" >/dev/null; then
  echo "creating group $APP_GROUP"
  groupadd --system "$APP_GROUP"
fi

if ! getent passwd "$APP_USER" >/dev/null; then
  echo "creating user $APP_USER (home $APP_DIR)"
  useradd --system --gid "$APP_GROUP" --home-dir "$APP_DIR" \
    --shell /usr/sbin/nologin "$APP_USER"
fi

# Scrutineer runs docker commands for per-scan containers, so the service
# account needs docker group membership. Create the group if the docker
# package has not yet (it normally owns /var/run/docker.sock's group).
if ! getent group docker >/dev/null; then
  echo "creating group docker"
  groupadd --system docker
fi
echo "adding $APP_USER to docker group"
usermod -aG docker "$APP_USER"

# --- application directory --------------------------------------------------
# $APP_DIR is a git checkout of this repo (populated by deploy.sh). bin/ holds
# the compiled binaries + rendered secret env files.
mkdir -p "$APP_DIR/bin"
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

# --- systemd units ----------------------------------------------------------
for unit in scrutineer.service scrutineer-sharing.service; do
  echo "installing $unit"
  install -m 0644 "$SRC_DIR/$unit" "$UNIT_DIR/$unit"
done

systemctl daemon-reload
systemctl enable scrutineer.service scrutineer-sharing.service

echo "install.sh: host setup complete"
