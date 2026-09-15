# Web Audit Dashboard

Next.js (App Router) front end for the Scanner Engine. One input, one scan, one
graded score.

## How a scan flows

```
browser ──POST /api/scan──▶ Next.js Route Handler ──POST /scan/full──▶ Scanner Engine
   ▲                          (holds SCANNER_API_KEY)                    (Oracle Cloud)
   └──────────────── JSON: score + per-module findings ──────────────────┘
```

**The browser never calls the scanner directly.** `SCANNER_API_KEY` is read only
inside `app/api/scan/route.ts`, which runs on the server — a `NEXT_PUBLIC_`
variable would ship the credential to every visitor and let anyone run scans on
our infrastructure. That is also why the scan goes through a Route Handler
instead of `fetch`ing the engine from the client.

## Local development

```bash
cd web
npm install
cp .env.example .env.local     # point SCANNER_URL at a running engine
npm run dev                    # http://localhost:3000
```

Start the engine first (from the repository root):

```bash
uvicorn main:app --reload      # or: docker compose up -d
```

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_URL` | `http://localhost:8000` | Base URL of the Scanner Engine |
| `SCANNER_API_KEY` | – | Sent as `X-API-Key`; must match the engine's `API_KEY` |
| `SCANNER_TIMEOUT` | `45` | Seconds to wait for a full scan |

## Deploying to Vercel

1. Import the repository, set **Root Directory** to `web`.
2. Add `SCANNER_URL`, `SCANNER_API_KEY` and `SCANNER_TIMEOUT` as environment
   variables (all three are server-side; do not prefix them with `NEXT_PUBLIC_`).
3. Deploy. Every push to the branch redeploys automatically.

`SCANNER_URL` must be **https** in production, which means the engine needs a
domain and a certificate — put Caddy in front of it on the Oracle instance
(`scanner.<your-domain> { reverse_proxy scanner-engine:8000 }`). A Vercel
deployment on https cannot call an http origin; the browser is not involved in
that call, but Vercel's own fetch will still travel the public internet, so the
API key would otherwise cross it in clear text.

Then narrow the engine's CORS list from `*` to the Vercel origin — see
`main.py`.

## Design notes

* **Status colour never carries meaning alone.** Every verdict is an icon plus a
  word plus a colour, and the colour sits on a dot or an arc, never on the text —
  so the page reads correctly in greyscale, in forced-colors mode, and for
  colour-blind users. The palette is the reserved status set (good / warning /
  serious / critical), defined once as CSS custom properties in `globals.css`.
* **Dark mode is a selected palette**, not an inverted one, and it is declared
  under both `prefers-color-scheme` and an explicit `[data-theme]` stamp so a
  future toggle wins in both directions.
* **The dial has a table beside it.** The gauge is a hero number, not a chart —
  the breakdown table answers "why is my score 78?" and doubles as the
  colour-free view of the same data.
* **`coverage` is shown whenever it is below 100%.** A score of 100 computed
  from half the model is not the same claim as a score of 100 from all of it,
  and the dashboard says so rather than quietly rounding the difference away.

## Not built yet

Sign-in (Supabase Auth), saved domains and the score-history chart. The engine
already writes `scans`, `scan_results` and `scores` rows, and RLS is in place,
so the history page is a read away — it just needs the auth session to scope it.
