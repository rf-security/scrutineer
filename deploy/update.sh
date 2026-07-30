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
TOOLCHAIN_DIR="$APP_DIR/toolchain"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_STAGE="${SECRET_STAGE:-}"

if [[ $EUID -ne 0 ]]; then
  echo "update.sh must run as root (use sudo)" >&2
  exit 1
fi

# --- host setup + units (idempotent) ---------------------------------------
bash "$SRC_DIR/install.sh"

# --- go toolchain -----------------------------------------------------------
# The instance's system Go can be far older than the module's required
# `toolchain` (and pre-1.21 Go cannot auto-download it), so provision the exact
# version pinned in go.mod under $TOOLCHAIN_DIR, once, and build with it.
# go build also needs the module root (repo root = parent of deploy/) as cwd.
REPO_ROOT="$(dirname "$SRC_DIR")"
cd "$REPO_ROOT"

want="$(awk '/^toolchain /{print $2; exit}' go.mod)"       # e.g. go1.26.5
if [[ -z "$want" ]]; then
  want="go$(awk '/^go /{print $2; exit}' go.mod)"          # fallback: go directive
fi
case "$(uname -m)" in
  x86_64)  goarch=amd64 ;;
  aarch64) goarch=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac
GO_ROOT="$TOOLCHAIN_DIR/$want"
GO_BIN="$GO_ROOT/bin/go"
if [[ ! -x "$GO_BIN" ]]; then
  echo "==> installing Go toolchain $want ($goarch)"
  mkdir -p "$TOOLCHAIN_DIR"
  tmp="$(mktemp -d)"
  curl -fsSL "https://go.dev/dl/${want}.linux-${goarch}.tar.gz" -o "$tmp/go.tgz"
  rm -rf "$GO_ROOT"; mkdir -p "$GO_ROOT"
  tar -C "$GO_ROOT" --strip-components=1 -xzf "$tmp/go.tgz"
  rm -rf "$tmp"
fi
echo "==> using $("$GO_BIN" version)"

# --- build binaries ---------------------------------------------------------
# Build as the service account so the module/build cache lives under its $HOME
# and the binaries are owned correctly. GOTOOLCHAIN=local pins the toolchain we
# just installed (already matching go.mod) so the build never fetches another.
echo "==> building binaries into $BIN_DIR (from $REPO_ROOT)"
install -d -o "$APP_USER" -g "$APP_GROUP" "$BIN_DIR"
build() { # dst pkg
  sudo -u "$APP_USER" env HOME="$APP_DIR" GOTOOLCHAIN=local GOFLAGS=-mod=mod \
    PATH="$GO_ROOT/bin:/usr/bin:/bin" \
    "$GO_BIN" build -o "$1" "$2"
}
build "$BIN_DIR/scrutineer"         ./cmd/scrutineer
build "$BIN_DIR/scrutineer-sharing" ./cmd/sharing

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
