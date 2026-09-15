# Scanner Engine

DNSSEC and email-authentication (SPF / DMARC) scanning API for the Web Audit
Platform. FastAPI + dnspython, results persisted to Supabase, packaged for
ARM64 (Oracle Cloud Ampere A1).

```
main.py                  FastAPI app: routes, auth, scan pipeline
app/config.py            Environment-driven settings
app/schemas.py           Request/response models
app/dns_client.py        Resolver construction + dnspython error mapping
app/scanners/dnssec.py   DS / DNSKEY / RRSIG / AD-flag checks
app/scanners/email_auth.py  SPF + DMARC lookup and grading
app/scanners/tls.py      Certificate chain, expiry, protocol versions, HSTS
app/storage.py           Supabase insert (best effort)
supabase/schema.sql      Table DDL
tests/                   Offline unit tests
```

## Endpoints

| Method | Path          | Body                        | Purpose                              |
|--------|---------------|-----------------------------|--------------------------------------|
| GET    | `/health`     | –                           | Liveness probe + Supabase status     |
| POST   | `/scan/dns`   | `{"domain": "example.com"}` | DNSSEC chain-of-trust validation     |
| POST   | `/scan/email` | `{"domain": "example.com"}` | SPF + DMARC validation               |
| POST   | `/scan/tls`   | `{"domain": "example.com"}` | Certificate, protocols, HSTS (optional `"port": 443`) |
| GET    | `/docs`       | –                           | Swagger UI                           |

Every scan returns the same envelope:

```json
{
  "domain": "example.com",
  "scan_type": "dnssec",
  "status": "pass",
  "summary": "DNSSEC is enabled and the chain of trust validates.",
  "findings": [],
  "raw_data": { "checks": { "ds_present": true, "...": "..." } },
  "scanned_at": "2026-09-15T05:51:42Z",
  "persisted": true,
  "record_id": 42
}
```

`status` is one of `pass` (configured and valid), `warn` (present but weak,
e.g. `p=none` or `?all`), `fail` (missing or broken), `error` (undeterminable —
NXDOMAIN, timeout, dead nameserver).

### What the DNSSEC scan actually checks

1. **DS** record exists in the parent zone (the delegation is signed).
2. **DNSKEY** RRset exists at the apex.
3. **RRSIG** covering the DNSKEY RRset exists, is not expired, and verifies
   cryptographically against those keys (`dns.dnssec.validate`). A signature
   that is still valid but expires within `DNSSEC_EXPIRY_WARNING_DAYS`
   (default 14) downgrades the result to `warn` — an expired RRSIG takes the
   whole domain offline for every validating resolver, so the alarm has to come
   *before* that happens, not after. `raw_data.min_days_until_expiry` carries
   the countdown for the dashboard.
4. At least one DS digest **matches** a published DNSKEY — this catches the
   common "stale DS at the registrar after a key rollover" breakage.
5. The validating resolver set the **AD** flag on the response.

A zone that is signed but does not validate is reported as `fail` with the
specific reason, never silently as "not enabled".

### What the email scan checks

* SPF: exactly one `v=spf1` TXT record at the apex; the `all` qualifier
  (`+all` / `?all` → `warn`); the RFC 7208 10-DNS-lookup limit; duplicate
  records (which are a permerror).
* DMARC: a single `v=DMARC1` record at `_dmarc.<domain>`; `p=` policy strength,
  `pct<100`, missing `rua`, and an `sp=none` that undercuts the parent policy.

### What the TLS scan checks

* **Trust**: does the certificate verify against the system trust store the way
  a browser would — expired, self-signed, wrong hostname, or a missing
  intermediate all land here. When verification fails the scanner reconnects
  without verification so it can still report *why*.
* **Expiry**: `days_until_expiry` (negative once expired) with a `warn` inside
  `TLS_EXPIRY_WARNING_DAYS` (default 30 — Let's Encrypt renews at 30 days left,
  so anything under that is already late).
* **Protocols**: each of TLS 1.0/1.1/1.2/1.3 is probed separately. Accepting
  TLS 1.0 or 1.1 (deprecated by RFC 8996) is a `warn`; no TLS 1.2+ at all is a
  `fail`. A probe that the *local* OpenSSL cannot perform reports `null`, not
  `false` — the scanner does not claim a verdict it could not establish.
* **Certificate hygiene**: key type and size, signature algorithm (MD5/SHA-1
  fail), and a validity period over the 398 days browsers accept.
* **HSTS**: the `Strict-Transport-Security` header and its `max-age`.

Only the standard library plus `cryptography` (already needed for DNSSEC) is
used — no openssl binary to shell out to.

## Supabase setup

Run `supabase/schema.sql` in the SQL editor:

```sql
create table if not exists public.scan_results (
    id bigint generated always as identity primary key,
    domain text not null,
    scan_type text not null,
    status text not null,
    summary text,
    findings jsonb not null default '[]'::jsonb,
    raw_data jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
```

Copy `.env.example` to `.env` and fill in `SUPABASE_URL` and `SUPABASE_KEY`
(use the **service-role** key — it is server-side only and bypasses RLS).
Persistence is best effort: if Supabase is unreachable the scan still returns,
with `"persisted": false`.

## Running with Docker Compose

On an Oracle Cloud Ampere A1 instance (Ubuntu 22.04/24.04, `aarch64`):

```bash
# 1. Docker + Compose plugin
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker "$USER" && newgrp docker

# 2. Configure
git clone <this-repo> scanner-engine && cd scanner-engine
cp .env.example .env && nano .env      # add your Supabase URL + service key

# 3. Build and start
docker compose up -d --build

# 4. Verify
curl localhost:8000/health
curl -X POST localhost:8000/scan/dns   -H 'Content-Type: application/json' -d '{"domain":"cloudflare.com"}'
curl -X POST localhost:8000/scan/email -H 'Content-Type: application/json' -d '{"domain":"example.com"}'

# Logs / lifecycle
docker compose logs -f scanner-engine
docker compose restart scanner-engine
docker compose down
```

Notes:

* The image is a two-stage build on `python:3.11-slim-bookworm`, which is a
  multi-arch manifest — on an A1 instance it resolves to `linux/arm64`
  natively, so no emulation is involved. Compilers live only in the builder
  stage; the runtime stage ships just the virtualenv, and the app runs as the
  unprivileged `scanner` user.
* Building an ARM64 image from an x86 laptop needs emulation:
  `docker buildx build --platform linux/arm64 -t scanner-engine:latest .`
  (drop the `platform:` line in `docker-compose.yml` to build natively on x86).
* Outbound **UDP and TCP port 53** must be open. Oracle Cloud blocks most
  egress by default in the VCN security list *and* in the instance's local
  `iptables`:

  ```bash
  sudo iptables -I INPUT 1 -p tcp --dport 8000 -j ACCEPT
  sudo netfilter-persistent save
  ```

  Then add an ingress rule for TCP 8000 to the subnet's security list.
* Put a reverse proxy (Caddy/nginx) in front for TLS before exposing this
  publicly, and set `API_KEY` in `.env` so callers must send `X-API-Key`.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload      # http://localhost:8000/docs
pytest                         # offline unit tests
```

## Configuration

| Variable          | Default            | Meaning                                       |
|-------------------|--------------------|-----------------------------------------------|
| `SUPABASE_URL`    | –                  | Project URL                                    |
| `SUPABASE_KEY`    | –                  | Service-role key                               |
| `SUPABASE_TABLE`  | `scan_results`     | Destination table                              |
| `PERSIST_RESULTS` | `true`             | Set `false` to scan without writing            |
| `DNS_RESOLVERS`   | `1.1.1.1,8.8.8.8`  | Comma-separated validating resolvers           |
| `DNS_TIMEOUT`     | `5.0`              | Per-query timeout (seconds)                    |
| `DNS_LIFETIME`    | `10.0`             | Total time budget per query (seconds)          |
| `DNSSEC_EXPIRY_WARNING_DAYS` | `14`    | Warn this many days before an RRSIG expires    |
| `TLS_EXPIRY_WARNING_DAYS` | `30`       | Warn this many days before the certificate expires |
| `TLS_TIMEOUT`     | `8.0`              | TLS connect/handshake timeout (seconds)        |
| `API_KEY`         | – (disabled)       | When set, `X-API-Key` is required on `/scan/*` |
| `LOG_LEVEL`       | `INFO`             | Python log level                               |
