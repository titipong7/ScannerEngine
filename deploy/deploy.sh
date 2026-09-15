#!/usr/bin/env bash
#
# Deploy (or redeploy) the Scanner Engine on the Oracle instance.
#
#   bash deploy/deploy.sh            # pull, build, restart, verify
#   bash deploy/deploy.sh --no-pull  # deploy the working tree as it is
#
# Verifies the new container answers before declaring success, and rolls back to
# the previous image if it does not — a failed build should not take the running
# service down with it.

set -euo pipefail

cd "$(dirname "$0")/.."

log()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
die()  { printf '\033[31merror: %s\033[0m\n' "$1" >&2; exit 1; }

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.prod.yml)
PULL=true
[[ "${1:-}" == "--no-pull" ]] && PULL=false

# --- preflight ---------------------------------------------------------------
[[ -f .env ]] || die ".env is missing — copy .env.example and fill in SUPABASE_URL, SUPABASE_KEY, API_KEY, SCANNER_DOMAIN"

for required in SCANNER_DOMAIN API_KEY; do
	if ! grep -qE "^${required}=.+" .env; then
		die "$required is empty in .env — refusing to deploy a scanner anyone can drive"
	fi
done

docker compose version >/dev/null 2>&1 || die "docker compose plugin not found — run deploy/bootstrap.sh first"

# --- remember what is running, so a failure can be undone --------------------
PREVIOUS_IMAGE="$(docker inspect --format '{{.Image}}' scanner-engine 2>/dev/null || true)"

if $PULL; then
	log "Fetching the latest commit"
	git pull --ff-only
fi

log "Building and starting"
"${COMPOSE[@]}" up -d --build

# --- verify ------------------------------------------------------------------
log "Waiting for the engine to report healthy"
for attempt in $(seq 1 30); do
	state="$(docker inspect --format '{{.State.Health.Status}}' scanner-engine 2>/dev/null || echo missing)"
	[[ "$state" == "healthy" ]] && break
	[[ $attempt -eq 30 ]] && state=timeout
	sleep 2
done

if [[ "$state" != "healthy" ]]; then
	printf '\033[31mThe new container never became healthy (%s). Recent logs:\033[0m\n' "$state"
	"${COMPOSE[@]}" logs --tail 40 scanner-engine || true

	if [[ -n "$PREVIOUS_IMAGE" ]]; then
		log "Rolling back to the previous image"
		docker tag "$PREVIOUS_IMAGE" scanner-engine:latest
		"${COMPOSE[@]}" up -d --no-build scanner-engine
		die "rolled back — the previous version is running again"
	fi
	die "deployment failed and there was no previous image to roll back to"
fi

log "Checking the API through Caddy"
DOMAIN="$(grep -E '^SCANNER_DOMAIN=' .env | cut -d= -f2- | tr -d '"'"'"' ')"
if curl -fsS --max-time 10 "https://${DOMAIN}/health" >/dev/null 2>&1; then
	echo "https://${DOMAIN}/health: ok"
else
	printf '\033[33mThe engine is healthy but https://%s/health did not answer.\033[0m\n' "$DOMAIN"
	echo "Usually one of: DNS not pointing here yet, ports 80/443 closed in the VCN,"
	echo "or Caddy still obtaining a certificate. Check with:"
	echo "  ${COMPOSE[*]} logs --tail 40 caddy"
fi

log "Running"
"${COMPOSE[@]}" ps
docker image prune -f >/dev/null 2>&1 || true
