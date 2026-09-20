#!/usr/bin/env bash
#
# Run and test the production stack on your own machine.
#
#   bash deploy/local-stack.sh up      # build, start, wait, smoke test
#   bash deploy/local-stack.sh test    # smoke test whatever is already up
#   bash deploy/local-stack.sh logs
#   bash deploy/local-stack.sh down    # stop (add --clean to drop volumes)
#
# Same engine and same Caddyfile as production, on https://localhost:8443 with
# Caddy's internal certificate. Nothing here needs a domain, a public IP or an
# Oracle instance — the point is to find the problems that are yours before
# adding the ones that are the cloud's.

set -uo pipefail

cd "$(dirname "$0")/.."

log()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
die()  { printf '\033[31merror: %s\033[0m\n' "$1" >&2; exit 1; }

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.local.yml)
HTTPS_PORT="${LOCAL_HTTPS_PORT:-8443}"
BASE_URL="https://localhost:${HTTPS_PORT}"

ensure_env() {
	[[ -f .env ]] && return

	log "Creating .env for local testing"
	cp .env.example .env

	# A key is generated rather than left blank so the auth path is exercised —
	# running the stack wide open locally would skip the check that matters most
	# in production.
	local key
	key="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
	sed -i.bak "s|^API_KEY=.*|API_KEY=$key|" .env && rm -f .env.bak
	sed -i.bak "s|^SCANNER_DOMAIN=.*|SCANNER_DOMAIN=localhost|" .env && rm -f .env.bak

	warn "Supabase is not configured, so scans will run but not be stored."
	warn "Fill in SUPABASE_URL and SUPABASE_KEY in .env to test persistence too."
}

case "${1:-up}" in
	up)
		command -v docker >/dev/null || die "docker is not installed"
		docker compose version >/dev/null 2>&1 || die "the docker compose plugin is missing"
		docker info >/dev/null 2>&1 || die "the docker daemon is not running"

		ensure_env

		log "Building and starting"
		"${COMPOSE[@]}" up -d --build || die "compose failed — see the output above"

		log "Waiting for the engine"
		for attempt in $(seq 1 30); do
			state="$(docker inspect --format '{{.State.Health.Status}}' scanner-engine 2>/dev/null || echo missing)"
			[[ "$state" == "healthy" ]] && break
			[[ $attempt -eq 30 ]] && state=timeout
			sleep 2
		done

		if [[ "$state" != "healthy" ]]; then
			"${COMPOSE[@]}" logs --tail 40 scanner-engine
			die "the engine never became healthy ($state)"
		fi
		echo "engine: healthy"

		log "Waiting for Caddy to issue its internal certificate"
		for attempt in $(seq 1 20); do
			curl -sk --max-time 5 "$BASE_URL/health" >/dev/null 2>&1 && break
			sleep 2
		done

		exec "$0" test
		;;

	test)
		log "Smoke testing $BASE_URL"
		# --insecure is implied for localhost: the certificate is signed by
		# Caddy's own CA, which nothing on this machine has been told to trust.
		bash deploy/smoke-test.sh --url "$BASE_URL" "${@:2}"
		status=$?
		if [[ $status -ne 0 ]]; then
			warn ""
			warn "If the scanners failed but /health passed, the engine is fine and the"
			warn "network is not: check that outbound UDP *and* TCP port 53 are open."
			warn "  docker run --rm alpine sh -c 'apk add -q bind-tools && dig +short @1.1.1.1 example.com'"
		fi
		exit $status
		;;

	logs)
		"${COMPOSE[@]}" logs -f "${@:2}"
		;;

	down)
		if [[ "${2:-}" == "--clean" ]]; then
			log "Stopping and removing volumes"
			"${COMPOSE[@]}" down -v
		else
			log "Stopping"
			"${COMPOSE[@]}" down
		fi
		;;

	*)
		sed -n '2,14p' "$0" | sed 's/^# \?//'
		exit 2
		;;
esac
