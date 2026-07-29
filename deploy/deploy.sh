#!/usr/bin/env bash
#
# deploy.sh — roll out scrutineer + sharing to the GCE instance.
#
# Runs on the GitHub Actions runner (after google-github-actions/auth has set up
# gcloud creds). It:
#   1. Renders secrets + config locally from the `prod` environment secrets.
#   2. Ships them to the instance over an IAP SSH tunnel (never on a command
#      line, so nothing leaks into `ps` or gcloud audit logs).
#   3. Clones-or-fetches the target ref into /opt/scrutineer.
#   4. Runs deploy/update.sh on the instance: build binaries, install units,
#      install secrets, restart services.
#
# Required environment (the workflow wires these from vars/secrets):
#   GCP instance ...... INSTANCE (default scrutineer), ZONE (default us-central1-c)
#   Source ............ GITHUB_REPOSITORY (owner/repo), GITHUB_TOKEN, DEPLOY_REF
#                       (defaults to GITHUB_SHA), DEPLOY_BRANCH (default rf-deploy)
#   Secrets ........... CLAUDE_CODE_OAUTH_TOKEN
#                       SCRUTINEER_DB_SECRET, SCRUTINEER_DB_READONLY_SECRET
#                       SCRUTINEER_SHARING_GITHUB_CLIENT_ID
#                       SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET
#
# Set SCRUTINEER_NO_IAP=1 to SSH over the instance's external IP instead of IAP.
set -euo pipefail

INSTANCE="${INSTANCE:-scrutineer}"
ZONE="${ZONE:-us-central1-c}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-rf-deploy}"
DEPLOY_REF="${DEPLOY_REF:-${GITHUB_SHA:-}}"
APP_DIR=/opt/scrutineer
REMOTE_STAGE=/tmp/scrutineer-stage
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require() { # var
  if [[ -z "${!1:-}" ]]; then
    echo "deploy.sh: required env var $1 is empty" >&2
    exit 1
  fi
}
require GITHUB_REPOSITORY
require GITHUB_TOKEN
require CLAUDE_CODE_OAUTH_TOKEN
require SCRUTINEER_DB_SECRET
require SCRUTINEER_DB_READONLY_SECRET
require SCRUTINEER_SHARING_GITHUB_CLIENT_ID
require SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET

TUNNEL_FLAG="--tunnel-through-iap"
[[ "${SCRUTINEER_NO_IAP:-}" == "1" ]] && TUNNEL_FLAG=""

# --- stage secrets + config locally ----------------------------------------
WORK="$(mktemp -d)"
STAGE="$WORK/scrutineer-stage"
mkdir -p "$STAGE"
chmod 700 "$WORK" "$STAGE"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

umask 077

printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\n' "$CLAUDE_CODE_OAUTH_TOKEN" >"$STAGE/scrutineer.env"

{
  printf 'SCRUTINEER_SHARING_GITHUB_CLIENT_ID=%s\n' "$SCRUTINEER_SHARING_GITHUB_CLIENT_ID"
  printf 'SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET=%s\n' "$SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET"
} >"$STAGE/scrutineer-sharing.env"

# Render scrutineer.yaml from the committed template. Use python's literal
# str.replace (secrets passed via env, not argv) — bash ${//} and sed both
# treat characters like & specially and would corrupt the password.
python3 - "$SCRIPT_DIR/scrutineer.yaml" "$STAGE/scrutineer.yaml" <<'PY'
import os, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    text = f.read()
text = text.replace("__DB_PASSWORD__", os.environ["SCRUTINEER_DB_SECRET"])
text = text.replace("__DB_READONLY_PASSWORD__", os.environ["SCRUTINEER_DB_READONLY_SECRET"])
with open(dst, "w") as f:
    f.write(text)
PY

# Remote bootstrap script. Secrets embedded here live only inside the file
# (mode 600, deleted at the end) — never on a process command line.
CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
PLAIN_URL="https://github.com/${GITHUB_REPOSITORY}.git"
cat >"$STAGE/remote-bootstrap.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${APP_DIR}
STAGE=${REMOTE_STAGE}
BRANCH=${DEPLOY_BRANCH}
REF='${DEPLOY_REF}'

# Root operating on a checkout owned by the service account.
git config --global --add safe.directory "\$APP_DIR" || true

if [[ ! -d "\$APP_DIR/.git" ]]; then
  echo "==> cloning ${PLAIN_URL} into \$APP_DIR"
  mkdir -p "\$APP_DIR"
  git clone "${CLONE_URL}" "\$APP_DIR"
  git -C "\$APP_DIR" remote set-url origin "${PLAIN_URL}"   # scrub token from config
fi

echo "==> fetching \$BRANCH"
git -C "\$APP_DIR" fetch "${CLONE_URL}" "\$BRANCH"
if [[ -n "\$REF" ]]; then
  git -C "\$APP_DIR" reset --hard "\$REF"
else
  git -C "\$APP_DIR" reset --hard FETCH_HEAD
fi
echo "==> checked out \$(git -C "\$APP_DIR" rev-parse --short HEAD)"

echo "==> running update.sh"
SECRET_STAGE="\$STAGE" bash "\$APP_DIR/deploy/update.sh"

echo "==> cleaning up staged secrets"
rm -rf "\$STAGE"
EOF
chmod +x "$STAGE/remote-bootstrap.sh"

# --- ship + execute ---------------------------------------------------------
gcloud_common=(--zone "$ZONE" --quiet)
[[ -n "$TUNNEL_FLAG" ]] && gcloud_common+=("$TUNNEL_FLAG")

echo "==> staging files onto ${INSTANCE}:${REMOTE_STAGE}"
# scp cannot write to /tmp/scrutineer-stage if a stale one is root-owned; clear
# it first (the ssh user always owns what it created), then copy the dir in.
gcloud compute ssh "$INSTANCE" "${gcloud_common[@]}" \
  --command "rm -rf ${REMOTE_STAGE}"
gcloud compute scp --recurse "${gcloud_common[@]}" \
  "$STAGE" "${INSTANCE}:/tmp/"

echo "==> deploying on ${INSTANCE}"
gcloud compute ssh "$INSTANCE" "${gcloud_common[@]}" \
  --command "sudo bash ${REMOTE_STAGE}/remote-bootstrap.sh"

echo "==> deploy complete"
