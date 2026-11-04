#!/usr/bin/env bash
# Stop the local stack. Pass --wipe to also delete all data volumes.
set -euo pipefail
cd "$(dirname "$0")/../dev"
export PATH="$HOME/.docker/bin:$PATH"
if [[ "${1:-}" == "--wipe" ]]; then docker compose down -v; else docker compose down; fi
