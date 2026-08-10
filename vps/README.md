# Run everything on one small VPS

Replaces Render, Vercel and the Cloudflare relay hop with a single box running three containers
behind [Caddy](https://caddyserver.com), which obtains and renews HTTPS certificates on its own.

| Container | Purpose |
| --- | --- |
| `relay` | Portal API (`/stalker-proxy`) **and** the stream relay (`/proxy`) |
| `transcoder` | MKV/HEVC transcoding, built from the `smarter-iptv` repo |
| `caddy` | HTTPS termination and routing |

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
- **A domain or subdomain with an A record pointing at the server's IP.** This is not optional: the
  app is served over HTTPS, so browsers refuse to call a plain-HTTP address, and a certificate
  cannot be issued for a bare IP. A free subdomain (DuckDNS and similar) works fine.

## Install

```bash
ssh root@YOUR_SERVER_IP
curl -fsSL https://raw.githubusercontent.com/crickerr26/M26-ST-Player/main/vps/install.sh \
  | bash -s -- stream.example.com
```

It installs Docker, clones this repo to `/opt/m26`, generates `vps/.env`, opens ports 80/443 if
`ufw` is active, and starts everything. First run takes a few minutes, mostly building the
transcoder's ffmpeg image.

Verify:

```bash
curl https://stream.example.com/health
# {"ok":true,"service":"m26-stalker-relay","routes":["/stalker-proxy","/proxy"]}
```

## Point the app at it

In the app, under **Stream tools**:

| Setting | Value |
| --- | --- |
| Portal relay URL | `https://stream.example.com` |
| Transcoder server URL | `https://stream.example.com/transcoder` |

Then reconnect. Portal API, streams and transcoding all now come from your own box.

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
