#!/usr/bin/env bash
# Start the local Elastic Stack and print connection details.
set -euo pipefail
cd "$(dirname "$0")/../dev"

# Docker Desktop installs its CLI here but doesn't always add it to PATH.
export PATH="$HOME/.docker/bin:$PATH"
command -v docker >/dev/null || { echo "docker not found. Install Docker Desktop and start it."; exit 1; }

if [[ ! -f .env ]]; then
  rnd() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
  sed -e "s/^ELASTIC_PASSWORD=.*/ELASTIC_PASSWORD=$(rnd 20)/" \
      -e "s/^KIBANA_PASSWORD=.*/KIBANA_PASSWORD=$(rnd 20)/" \
      -e "s/^KIBANA_ENCRYPTION_KEY=.*/KIBANA_ENCRYPTION_KEY=$(rnd 40)/" \
      .env.example > .env
  echo "Created dev/.env with random passwords."
fi

docker compose up -d --wait
set -a; source .env; set +a
echo
echo "Elasticsearch: http://localhost:${ES_PORT}"
echo "Kibana:        http://localhost:${KIBANA_PORT}   (user: elastic, password in dev/.env)"
