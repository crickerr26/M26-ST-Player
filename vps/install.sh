#!/usr/bin/env bash
# One-shot setup for a fresh Ubuntu/Debian VPS: installs Docker, fetches this repo, and brings up
# the relay + stream proxy + transcoder behind Caddy with automatic HTTPS.
#
#   curl -fsSL https://raw.githubusercontent.com/crickerr26/M26-ST-Player/main/vps/install.sh | bash -s -- stream.example.com
#
# The argument is the domain that must already have an A record pointing at this server.
set -euo pipefail

DOMAIN="${1:-}"
APP_DIR="${APP_DIR:-/opt/m26}"
REPO="https://github.com/crickerr26/M26-ST-Player.git"

die() { echo "error: $*" >&2; exit 1; }
[ -n "$DOMAIN" ] || die "usage: install.sh <domain>   e.g. install.sh stream.example.com"
[ "$(id -u)" = "0" ] || die "run as root (or with sudo)"

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

Then in the app, under Stream tools:
    Portal relay URL      https://$DOMAIN
    Transcoder server URL https://$DOMAIN/transcoder

Useful:
    docker compose -f vps/docker-compose.yml logs -f
    docker compose -f vps/docker-compose.yml restart
    cd $APP_DIR && git pull && docker compose -f vps/docker-compose.yml up -d --build
DONE
