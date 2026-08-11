#!/usr/bin/env bash
# One-shot setup for a fresh Ubuntu/Debian VPS: installs Docker, fetches this repo, and brings up
# the relay + stream proxy + transcoder behind Caddy with automatic HTTPS.
#
#   curl -fsSL .../vps/install.sh | bash -s -- stream.example.com
#
# The argument is a domain with an A record pointing at this server. HTTPS is not optional here —
# the player is served over https and a browser will not let an https page pull video over http,
# and a certificate cannot be issued for a bare IP.
#
# No domain? Use a free DuckDNS one and pass its token as a second argument; the script points it
# at this machine and keeps it pointed:
#
#   curl -fsSL .../vps/install.sh | bash -s -- yourname.duckdns.org <duckdns-token>
set -euo pipefail

DOMAIN="${1:-}"
DUCK_TOKEN="${2:-}"
APP_DIR="${APP_DIR:-/opt/m26}"
REPO="https://github.com/crickerr26/M26-ST-Player.git"

die() { echo "error: $*" >&2; exit 1; }
[ -n "$DOMAIN" ] || die "usage: install.sh <domain> [duckdns-token]   e.g. install.sh stream.example.com"
[ "$(id -u)" = "0" ] || die "run as root (or with sudo)"

# DuckDNS first: the record has to point here before Caddy asks Let's Encrypt for a certificate,
# or the challenge fails and the whole run stalls on a cert it cannot get.
if [ -n "$DUCK_TOKEN" ]; then
  case "$DOMAIN" in
    *.duckdns.org) ;;
    *) die "a DuckDNS token was given but $DOMAIN is not a .duckdns.org name" ;;
  esac
  SUB="${DOMAIN%.duckdns.org}"
  echo "==> Pointing $DOMAIN at this server"
  RESP="$(curl -fsS "https://www.duckdns.org/update?domains=$SUB&token=$DUCK_TOKEN&ip=" || true)"
  [ "$RESP" = "OK" ] || die "DuckDNS refused the update (replied: ${RESP:-nothing}). Check the subdomain and token."
  # a VPS IP can change; keep the record current
  cat > /usr/local/bin/m26-duckdns <<DUCK
#!/bin/sh
curl -fsS "https://www.duckdns.org/update?domains=$SUB&token=$DUCK_TOKEN&ip=" >/dev/null 2>&1
DUCK
  chmod +x /usr/local/bin/m26-duckdns
  ( crontab -l 2>/dev/null | grep -v m26-duckdns; echo "*/5 * * * * /usr/local/bin/m26-duckdns" ) | crontab -
  echo "    done, and refreshed every 5 minutes"
fi

echo "==> Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  echo "==> Installing Docker"
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"

echo "==> Fetching $REPO into $APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  git clone --depth 1 "$REPO" "$APP_DIR"
fi

cd "$APP_DIR"
if [ ! -f vps/.env ]; then
  echo "==> Writing vps/.env"
  { echo "DOMAIN=$DOMAIN"; echo "ACCESS_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"; } > vps/.env
else
  echo "==> Keeping existing vps/.env (delete it to regenerate)"
fi

# Caddy needs 80 and 443 to answer the ACME challenge and serve traffic.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "==> Opening 80/443 in ufw"
  ufw allow 80/tcp  >/dev/null || true
  ufw allow 443/tcp >/dev/null || true
fi

echo "==> Building and starting"
docker compose -f vps/docker-compose.yml --env-file vps/.env up -d --build

cat <<DONE

==> Done.

Certificate issuance takes a few seconds the first time. Check it worked:

    curl https://$DOMAIN/health

Expect: {"ok":true,"service":"m26-stalker-relay","routes":["/stalker-proxy","/proxy"]}

Open the player at:

    https://$DOMAIN

Use that address from now on rather than the Vercel or workers.dev one. The app, the portal API
and the video all come from this box, which is the point — a portal issues a stream link to
whichever address asked for it, so the link is created and played by the same machine.

Nothing needs configuring in Stream tools; the app finds these on its own origin. The transcoder,
for formats a browser cannot decode, is at https://$DOMAIN/transcoder

Useful:
    docker compose -f vps/docker-compose.yml logs -f
    docker compose -f vps/docker-compose.yml restart
    cd $APP_DIR && git pull && docker compose -f vps/docker-compose.yml up -d --build
DONE
