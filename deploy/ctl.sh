#!/usr/bin/env bash
#
# ctl.sh — convenience wrapper to operate both scrutineer services at once.
#
#   ./deploy/ctl.sh start|stop|restart|status|enable|disable
#   ./deploy/ctl.sh logs [scrutineer|sharing]   # follow journal (both by default)
#
set -euo pipefail

UNITS=(scrutineer.service scrutineer-sharing.service)
cmd="${1:-status}"

case "$cmd" in
  start|stop|restart|enable|disable)
    exec systemctl "$cmd" "${UNITS[@]}"
    ;;
  status)
    exec systemctl --no-pager status "${UNITS[@]}"
    ;;
  logs)
    case "${2:-both}" in
      scrutineer) exec journalctl -fu scrutineer.service ;;
      sharing)    exec journalctl -fu scrutineer-sharing.service ;;
      both|"")    exec journalctl -f -u scrutineer.service -u scrutineer-sharing.service ;;
      *) echo "unknown log target: $2 (use scrutineer|sharing|both)" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status|enable|disable|logs [scrutineer|sharing]}" >&2
    exit 1
    ;;
esac
