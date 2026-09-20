#!/usr/bin/env bash
#
# Exercise a running Scanner Engine end to end.
#
#   bash deploy/smoke-test.sh                          # reads .env
#   bash deploy/smoke-test.sh --url http://localhost:8000
#   bash deploy/smoke-test.sh --url https://localhost --insecure --tls-suite
#
# Written to be run against anything: a bare uvicorn on your laptop, the local
# Caddy stack, or the real Oracle instance. Every assertion is about behaviour a
# user would notice, so a pass here means the deployment actually works — not
# just that the process started.

set -uo pipefail

cd "$(dirname "$0")/.."

BASE_URL=""
API_KEY=""
INSECURE=false
TLS_SUITE=false

while [[ $# -gt 0 ]]; do
	case "$1" in
		--url)       BASE_URL="$2"; shift 2 ;;
		--key)       API_KEY="$2"; shift 2 ;;
		--insecure)  INSECURE=true; shift ;;
		--tls-suite) TLS_SUITE=true; shift ;;
		-h|--help)   sed -n '2,14p' "$0" | sed 's/^# \?//'; exit 0 ;;
		*)           echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

# Fall back to .env for whatever was not passed in.
if [[ -f .env ]]; then
	env_value() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- | tr -d '"'"'"' '; }
	[[ -z "$API_KEY"  ]] && API_KEY="$(env_value API_KEY)"
	if [[ -z "$BASE_URL" ]]; then
		domain="$(env_value SCANNER_DOMAIN)"
		[[ -n "$domain" ]] && BASE_URL="https://$domain"
	fi
fi
BASE_URL="${BASE_URL:-http://localhost:8000}"
BASE_URL="${BASE_URL%/}"

# Caddy signs localhost with its own internal CA, which curl has no reason to
# trust — that is expected, not a finding.
[[ "$BASE_URL" == https://localhost* || "$BASE_URL" == https://127.0.0.1* ]] && INSECURE=true

CURL=(curl -sS --max-time 90)
$INSECURE && CURL+=(--insecure)

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
passed=0
failed=0
STATUS=""
BODY=""
declare -a failures=()

ok()   { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$1"; passed=$((passed + 1)); }
bad()  { printf '  %s✗%s %s\n    %s%s%s\n' "$RED" "$OFF" "$1" "$DIM" "$2" "$OFF"
         failed=$((failed + 1)); failures+=("$1"); }
note() { printf '  %s· %s%s\n' "$DIM" "$1" "$OFF"; }
head_() { printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }

# post <path> <json> -> "<http status>\n<body>" on stdout.
#
# The status travels with the body on purpose: post() is always called inside a
# command substitution, which is a subshell, so anything it assigns to a global
# is lost. Pair it with `split_response`.
post() {
	local path="$1" payload="$2" response
	local args=("${CURL[@]}" -w '\n%{http_code}' -X POST "$BASE_URL$path"
	            -H 'Content-Type: application/json' -d "$payload")
	[[ -n "$API_KEY" ]] && args+=(-H "X-API-Key: $API_KEY")
	response="$("${args[@]}" 2>&1)"
	printf '%s\n%s' "${response##*$'\n'}" "${response%$'\n'*}"
}

# split_response <captured> -> sets $STATUS and $BODY in the *caller's* scope
split_response() {
	STATUS="${1%%$'\n'*}"
	BODY="${1#*$'\n'}"
}

# Read one value out of a JSON body. Returns empty on anything unparseable.
jget() {
	python3 -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
for key in sys.argv[1].split("."):
    if isinstance(data, list):
        data = data[int(key)] if key.isdigit() and int(key) < len(data) else None
    elif isinstance(data, dict):
        data = data.get(key)
    else:
        data = None
    if data is None:
        sys.exit(0)
print(data)
' "$1" 2>/dev/null
}

printf '%sScanner Engine smoke test%s\n' "$BOLD" "$OFF"
printf '%starget: %s   api key: %s%s\n' "$DIM" "$BASE_URL" \
       "$([[ -n "$API_KEY" ]] && echo "yes" || echo "none")" "$OFF"

# --------------------------------------------------------------------------- #
head_ "Reachability"
# --------------------------------------------------------------------------- #
health="$("${CURL[@]}" -w '\n%{http_code}' "$BASE_URL/health" 2>&1)"
health_status="${health##*$'\n'}"
health_body="${health%$'\n'*}"

if [[ "$health_status" != "200" ]]; then
	bad "GET /health answers" "got HTTP ${health_status:-no response}: ${health_body:0:200}"
	printf '\n%sNothing else can pass while the engine is unreachable. Check:%s\n' "$RED" "$OFF"
	echo "  docker compose -f docker-compose.yml -f docker-compose.prod.yml ps"
	echo "  docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail 40"
	exit 1
fi
ok "GET /health answers 200"

[[ "$(printf '%s' "$health_body" | jget status)" == "ok" ]] &&
	ok "health reports status ok" ||
	bad "health reports status ok" "body: ${health_body:0:200}"

supabase="$(printf '%s' "$health_body" | jget supabase)"
if [[ "$supabase" == "connected" ]]; then
	ok "Supabase is configured"
else
	note "Supabase is $supabase — scans will return persisted:false (fine for a smoke test)"
fi

# --------------------------------------------------------------------------- #
head_ "Authentication"
# --------------------------------------------------------------------------- #
if [[ -n "$API_KEY" ]]; then
	nokey_status="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/scan/dns" \
	                -H 'Content-Type: application/json' -d '{"domain":"example.com"}' 2>&1)"
	[[ "$nokey_status" == "401" ]] &&
		ok "a request with no X-API-Key is rejected (401)" ||
		bad "a request with no X-API-Key is rejected" "got $nokey_status — the scanner is open to anyone"

	badkey_status="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/scan/dns" \
	                 -H 'Content-Type: application/json' -H 'X-API-Key: definitely-wrong' \
	                 -d '{"domain":"example.com"}' 2>&1)"
	[[ "$badkey_status" == "401" ]] &&
		ok "a wrong X-API-Key is rejected (401)" ||
		bad "a wrong X-API-Key is rejected" "got $badkey_status"
else
	note "no API_KEY set, so the auth checks are skipped — do not deploy it this way"
fi

# --------------------------------------------------------------------------- #
head_ "Input validation"
# --------------------------------------------------------------------------- #
split_response "$(post /scan/dns '{"domain":"not a domain"}')"
[[ "$STATUS" == "422" ]] && ok "a malformed domain is rejected (422)" ||
	bad "a malformed domain is rejected" "got $STATUS"

split_response "$(post /scan/dns '{}')"
[[ "$STATUS" == "422" ]] && ok "a missing domain is rejected (422)" ||
	bad "a missing domain is rejected" "got $STATUS"

split_response "$(post /scan/email '{"domain":"HTTPS://Example.COM/pricing?x=1"}')"
[[ "$(printf '%s' "$BODY" | jget domain)" == "example.com" ]] &&
	ok "a pasted URL is normalised to a bare domain" ||
	bad "a pasted URL is normalised" "got '$(printf '%s' "$BODY" | jget domain)' (HTTP $STATUS)"

# --------------------------------------------------------------------------- #
head_ "Scanners"
# --------------------------------------------------------------------------- #
check_scan() {                 # check_scan <label> <path> <json> <expected status>
	local label="$1" path="$2" payload="$3" expected="$4" actual summary
	split_response "$(post "$path" "$payload")"
	if [[ "$STATUS" != "200" ]]; then
		bad "$label" "HTTP $STATUS: ${BODY:0:200}"
		return
	fi
	actual="$(printf '%s' "$BODY" | jget status)"
	summary="$(printf '%s' "$BODY" | jget summary)"
	if [[ "$actual" == "$expected" ]]; then
		ok "$label → $actual"
		note "$summary"
	else
		bad "$label → expected $expected" "got '$actual': $summary"
	fi
}

check_scan "DNSSEC on a signed zone (cloudflare.com)" /scan/dns '{"domain":"cloudflare.com"}' pass
check_scan "DNSSEC on an unsigned zone (google.com)"  /scan/dns '{"domain":"google.com"}'     fail
check_scan "DNSSEC on a broken zone (dnssec-failed.org)" /scan/dns '{"domain":"dnssec-failed.org"}' fail

split_response "$(post /scan/email '{"domain":"example.com"}')"
spf="$(printf '%s' "$BODY" | jget raw_data.spf.records.0)"
if [[ -n "$spf" ]]; then
	ok "SPF record is read (example.com)"
	note "$spf"
else
	bad "SPF record is read" "no record parsed — if this times out, outbound TCP 53 is blocked"
fi

split_response "$(post /scan/dkim '{"domain":"github.com"}')"
dkim_status="$(printf '%s' "$BODY" | jget status)"
if [[ "$dkim_status" == "pass" || "$dkim_status" == "warn" ]]; then
	ok "DKIM key found by selector sweep (github.com) → $dkim_status"
else
	bad "DKIM key found by selector sweep" "got '$dkim_status' — expected pass or warn"
fi

split_response "$(post /scan/dkim '{"domain":"github.com","selectors":["definitely-not-a-selector"]}')"
[[ "$(printf '%s' "$BODY" | jget status)" == "fail" ]] &&
	ok "a named selector with no key fails (as opposed to a guessed one)" ||
	bad "a named selector with no key fails" "got '$(printf '%s' "$BODY" | jget status)'"

# --------------------------------------------------------------------------- #
head_ "Full scan and scoring"
# --------------------------------------------------------------------------- #
split_response "$(post /scan/full '{"domain":"example.com"}')"
if [[ "$STATUS" != "200" ]]; then
	bad "POST /scan/full" "HTTP $STATUS: ${BODY:0:200}"
else
	score="$(printf '%s' "$BODY" | jget score.score)"
	grade="$(printf '%s' "$BODY" | jget score.grade)"
	coverage="$(printf '%s' "$BODY" | jget score.coverage)"
	duration="$(printf '%s' "$BODY" | jget duration_ms)"
	modules="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["modules"]))' 2>/dev/null)"

	[[ "$score" =~ ^[0-9]+$ ]] &&
		ok "full scan returns a score ($score, grade $grade, coverage $coverage, ${duration}ms)" ||
		bad "full scan returns a score" "score was '$score' — every module may have failed"

	[[ "$modules" == "4" ]] &&
		ok "all four modules ran" ||
		bad "all four modules ran" "got $modules"

	persisted="$(printf '%s' "$BODY" | jget persisted)"
	if [[ "$supabase" == "connected" ]]; then
		[[ "$persisted" == "True" ]] &&
			ok "the result was stored in Supabase" ||
			bad "the result was stored in Supabase" "persisted=$persisted — check the key and that schema.sql has been run"
	fi
fi

# --------------------------------------------------------------------------- #
if $TLS_SUITE; then
head_ "TLS verdicts (badssl.com)"
	note "these need direct TLS to the internet; a corporate proxy that intercepts"
	note "TLS will make every one of them pass, which is a false negative"
	for host in expired.badssl.com self-signed.badssl.com wrong.host.badssl.com; do
		check_scan "TLS on $host" /scan/tls "{\"domain\":\"$host\"}" fail
	done
	check_scan "TLS on a healthy host (cloudflare.com)" /scan/tls '{"domain":"cloudflare.com"}' pass
fi

# --------------------------------------------------------------------------- #
printf '\n%s%d passed, %d failed%s\n' "$BOLD" "$passed" "$failed" "$OFF"
if [[ $failed -gt 0 ]]; then
	printf '%sfailed:%s\n' "$RED" "$OFF"
	printf '  - %s\n' "${failures[@]}"
	exit 1
fi
printf '%sEverything the engine promises, it did.%s\n' "$GREEN" "$OFF"
