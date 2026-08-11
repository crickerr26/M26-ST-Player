# Run everything on one small VPS

Replaces Render, Vercel and the Cloudflare relay hop with a single box running three containers
behind [Caddy](https://caddyserver.com), which obtains and renews HTTPS certificates on its own.

| Container | Purpose |
| --- | --- |
| `relay` | Portal API (`/stalker-proxy`) **and** the stream relay (`/proxy`) |
| `transcoder` | MKV/HEVC transcoding, built from the `smarter-iptv` repo |
| `caddy` | HTTPS, routing, **and serving the player itself** |

Caddy serves the app from this box too, so the player, the portal API and the video all share one
origin. That is the main reason to run it: a Stalker portal issues a stream link to whichever
address asked for it, so the request that creates the link and the request that plays it have to
come from the same place. Split across Vercel and a Worker they never can.

## Why a VPS

Every free tier fails on a different axis, and video finds all of them:

- **Render free** — 5 GB/month. Video exhausts that in hours; the workspace then suspends and takes
  the transcoder with it.
- **Vercel / any serverless** — functions cap out around a minute. Fine for portal API calls,
  useless for a live channel that runs for hours.
- **Cloudflare Workers** — excellent at streaming, but the portal API calls were being refused from
  it, which is what started this.

A €4/month box with ~20 TB of traffic sidesteps all three at once, and nothing sleeps.

## Requirements

- A fresh Ubuntu or Debian VPS (Hetzner CX22 or similar; 2 vCPU / 4 GB is ample).
- **A domain or subdomain pointing at the server.** Not optional: the player is served over HTTPS,
  a browser will not let an HTTPS page pull video over HTTP, and no certificate can be issued for a
  bare IP.
  **No domain?** Register a free one at [duckdns.org](https://www.duckdns.org), and pass its token
  as a second argument — the installer points the record at this machine and keeps it pointed
  (VPS addresses change).

## Install

```bash
ssh root@YOUR_SERVER_IP

# with your own domain
curl -fsSL https://raw.githubusercontent.com/crickerr26/M26-ST-Player/main/vps/install.sh \
  | bash -s -- stream.example.com

# or with a free DuckDNS name
curl -fsSL https://raw.githubusercontent.com/crickerr26/M26-ST-Player/main/vps/install.sh \
  | bash -s -- yourname.duckdns.org YOUR_DUCKDNS_TOKEN
```

It installs Docker, clones this repo to `/opt/m26`, generates `vps/.env`, opens ports 80/443 if
`ufw` is active, and starts everything. First run takes a few minutes, mostly building the
transcoder's ffmpeg image.

Verify:

```bash
curl https://stream.example.com/health
# {"ok":true,"service":"m26-stalker-relay","routes":["/stalker-proxy","/proxy"]}
```

## Using it

Open **`https://your-domain`** and use that instead of the Vercel or workers.dev address.

**There is nothing to configure.** The app finds the portal API and the stream relay on its own
origin, which is exactly what makes the link work: both requests leave from this machine. Leave
**Portal relay URL** empty.

The only optional setting is **Transcoder server URL** → `https://your-domain/transcoder`, for
formats a browser cannot decode (MKV, HEVC). Everything else needs no setup.

## Operating it

```bash
cd /opt/m26
docker compose -f vps/docker-compose.yml logs -f          # follow logs
docker compose -f vps/docker-compose.yml restart          # restart
git pull && docker compose -f vps/docker-compose.yml up -d --build   # update
```

`restart: unless-stopped` on every container means the stack comes back by itself after a reboot.

## Notes

- The stream relay refuses private, loopback, link-local and cloud-metadata targets, so it can't be
  turned into a probe of the server's own network.
- Caddy disables the proxy read timeout on `/proxy` and `/transcoder/`. Without that a live channel
  is cut off mid-programme when the default timeout expires.
- The transcoder writes HLS segments to a 4 GB tmpfs, so churn stays in RAM and never touches the
  disk.
- `ACCESS_TOKEN` is generated during install and guards the transcoder's admin routes. It lives in
  `vps/.env`, which is not committed.
