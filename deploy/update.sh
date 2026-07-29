#!/usr/bin/env bash
#
# update.sh — build + (re)configure + restart the scrutineer services from the
# checkout already sitting in /opt/scrutineer. Runs ON the instance; deploy.sh
# invokes it over SSH after fetching the target ref.
#
#   sudo ./deploy/update.sh
#   sudo SECRET_STAGE=/tmp/scrutineer-stage ./deploy/update.sh
#
# When SECRET_STAGE points at a directory holding rendered secret files, they
# are installed into place:
#   $SECRET_STAGE/scrutineer.env          -> /opt/scrutineer/bin/scrutineer.env
#   $SECRET_STAGE/scrutineer-sharing.env  -> /opt/scrutineer/bin/scrutineer-sharing.env
#   $SECRET_STAGE/scrutineer.yaml         -> /opt/scrutineer/bin/scrutineer.yaml
# Absent files are left as-is (a re-run without secrets keeps the current ones).
set -euo pipefail

APP_USER=scrutineer
APP_GROUP=scrutineer
APP_DIR=/opt/scrutineer
BIN_DIR="$APP_DIR/bin"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_STAGE="${SECRET_STAGE:-}"

if [[ $EUID -ne 0 ]]; then
  echo "update.sh must run as root (use sudo)" >&2
  exit 1
fi

GO_BIN="$(command -v go || echo /usr/local/go/bin/go)"
if [[ ! -x "$GO_BIN" ]]; then
  echo "go toolchain not found (looked for 'go' on PATH and /usr/local/go/bin/go)" >&2
  exit 1
fi

# --- host setup + units (idempotent) ---------------------------------------
bash "$SRC_DIR/install.sh"

# --- build binaries ---------------------------------------------------------
# Build as the service account so the module/build cache lives under its $HOME
# and the resulting binaries are owned correctly. go build needs the module
# root (repo root = parent of deploy/) as the working directory.
REPO_ROOT="$(dirname "$SRC_DIR")"
cd "$REPO_ROOT"
echo "==> building binaries into $BIN_DIR (from $REPO_ROOT)"
install -d -o "$APP_USER" -g "$APP_GROUP" "$BIN_DIR"
sudo -u "$APP_USER" env HOME="$APP_DIR" PATH="$(dirname "$GO_BIN"):$PATH" GOFLAGS=-mod=mod \
  "$GO_BIN" build -o "$BIN_DIR/scrutineer" ./cmd/scrutineer
sudo -u "$APP_USER" env HOME="$APP_DIR" PATH="$(dirname "$GO_BIN"):$PATH" GOFLAGS=-mod=mod \
  "$GO_BIN" build -o "$BIN_DIR/scrutineer-sharing" ./cmd/sharing

# --- secrets / config -------------------------------------------------------
if [[ -n "$SECRET_STAGE" ]]; then
  install_secret() { # src dst
    if [[ -f "$1" ]]; then
      echo "==> installing $(basename "$2")"
      install -m 0600 -o "$APP_USER" -g "$APP_GROUP" "$1" "$2"
    fi
  }
  install_secret "$SECRET_STAGE/scrutineer.env"         "$BIN_DIR/scrutineer.env"
  install_secret "$SECRET_STAGE/scrutineer-sharing.env" "$BIN_DIR/scrutineer-sharing.env"
  install_secret "$SECRET_STAGE/scrutineer.yaml"        "$BIN_DIR/scrutineer.yaml"
fi

# --- restart ----------------------------------------------------------------
echo "==> restarting services"
systemctl restart scrutineer.service scrutineer-sharing.service

echo "==> status"
systemctl --no-pager --lines=0 status scrutineer.service scrutineer-sharing.service || true
