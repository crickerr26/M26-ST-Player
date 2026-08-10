# M26 Stalker relay

An optional, standalone copy of the `/stalker-proxy` route from `_worker.js`, meant to run
somewhere that is **not** Cloudflare.

## When you need this

You don't, unless portal logins or playlists are being refused.

The player is deployed on Cloudflare Workers, and IPTV portals are often behind Cloudflare too.
Portal API calls therefore reach the portal from Cloudflare's own network, carrying the MAG
set-top-box `User-Agent` the Stalker protocol requires. That combination can read as a bot and draw
a challenge — and a challenge replies with an HTML page instead of JSON, which surfaces in the app
as a login failure or an empty playlist.

Running this relay on an ordinary host makes those calls arrive from a normal datacenter IP
instead, sidestepping the Cloudflare-to-Cloudflare path.

**Confirm it's actually the problem first.** In the app, tap **Portal diagnostics → Run**. If you
see `← CLOUDFLARE CHALLENGE`, or 403s whose body is a Cloudflare page, this relay is worth
deploying. If the portal replies with normal JSON, the problem is elsewhere and this won't help.

## Deploy to Render

**Easiest:** in the app, open **Stream tools** and press **Deploy free relay**. That opens Render's
Blueprint flow against this repo, which reads `render.yaml` at the repo root and configures
everything (Node 20, `npm install`, `node server.js`, health check on `/health`, free plan).

**Manually**, if you prefer: on [render.com](https://render.com) → **New → Web Service** (not Static
Site — this has to run code) → connect this repository → set **Root Directory** to `relay` →
Deploy.

Either way, open the service URL when it finishes: `/health` should return `{"ok":true,...}`.
The free plan is fine; this carries small JSON API calls, not video.

Any Node host works — Fly.io, Railway, a VPS. There are no dependencies; it needs Node 18+ and a
`PORT` environment variable (defaults to 8080).

## Or deploy to Vercel instead (no Render account needed)

The repo also carries a serverless build of the same relay at `api/stalker-proxy.js`, so the whole
thing can be deployed straight to Vercel's free tier:

1. [vercel.com](https://vercel.com) → **Add New → Project** → import this repository.
2. Accept the defaults and **Deploy**. `vercel.json` maps `/stalker-proxy` onto the function, so the
   URL shape matches the Render build.

That deployment serves the **whole player** as well as the relay. If you open the app from the
Vercel URL, its built-in same-origin route already points at the function — **no relay URL needs
configuring at all**, and nothing touches Cloudflare. If you'd rather keep using the Cloudflare URL
for the app, just paste the Vercel URL into **Stream tools → Portal relay URL**.

Vercel's free tier includes far more bandwidth than portal API calls consume (they are kilobytes of
JSON), and functions do not sleep the way a free Render instance does.

> Free Render instances sleep when idle, so the first login after a quiet spell can take ~30s while
> the service wakes. Subsequent calls are fast.

## Point the app at it

In the app: **Stream tools → Portal relay URL** → paste the service URL
(e.g. `https://m26-stalker-relay.onrender.com`) → reconnect.

Leave the field empty to go back to the built-in same-origin route. Nothing else changes.

## Scope

Only portal **API** calls go through this relay. Video segments keep using whatever path the app
already uses, so a free instance is never asked to push streams.

Deliberately not an open proxy — the same guards as the Worker version:

- `GET` only
- only the four known Stalker loader paths (`portal.php`, `stalker_portal/server/load.php`,
  `server/load.php`, `c/portal.php`)
- a syntactically valid MAC is required
- `http`/`https` targets only, and private, loopback, link-local and cloud-metadata addresses are
  refused, so it can't be used to probe the network it's deployed in

Upstream status codes and bodies are passed through untouched — the app tells a portal auth refusal
apart from a firewall block by reading them, so neither may be normalised away here.
