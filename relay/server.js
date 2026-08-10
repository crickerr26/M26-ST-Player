/* M26 Stalker relay — a standalone copy of the /stalker-proxy route from _worker.js, meant to run
   somewhere that is NOT Cloudflare.

   Why this exists: the player is deployed on Cloudflare Workers, and the IPTV portals it talks to
   sit behind Cloudflare too. Portal calls therefore reach the origin from Cloudflare's own network
   carrying the MAG set-top-box User-Agent the Stalker protocol requires — which can read as a bot
   and draw a challenge, and a challenge answers with an HTML page instead of JSON. Running the
   relay on an ordinary host (Render, Fly, a VPS) makes the request arrive from a normal datacenter
   IP instead, sidestepping the Cloudflare-to-Cloudflare path entirely.

   Deliberately NOT an open proxy: only GET, only the fixed set of known Stalker loader scripts,
   only a syntactically valid MAC, and never to a private/loopback address. Same guards as the
   Worker version. Only the small JSON API calls belong here — video segments keep using whatever
   path the app already uses, so a free instance is not asked to push streams.

   No dependencies; Node 18+ (global fetch). Start: node server.js  (PORT from env, default 8080) */
'use strict';
const http = require('node:http');

const ENDPOINTS = new Set(['portal.php', 'stalker_portal/server/load.php', 'server/load.php', 'c/portal.php']);
const STB_UA = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';
const MAC_RE = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;
const PORT = Number(process.env.PORT) || 8080;

function cors(extra) {
  return Object.assign({
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,HEAD,OPTIONS',
    'access-control-allow-headers': 'accept,content-type,range,authorization',
    'access-control-expose-headers': 'content-length,content-type',
    'cross-origin-resource-policy': 'cross-origin',
    'timing-allow-origin': '*'
  }, extra || {});
}
function send(res, status, body, headers) {
  res.writeHead(status, cors(headers || { 'content-type': 'text/plain; charset=utf-8' }));
  res.end(body);
}
/* Same SSRF guard as the Worker's generic relay: a caller-supplied host must never be usable to
   probe whatever private network this happens to be deployed inside. */
function isPrivateHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '0.0.0.0' || h === '[::1]') return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;          // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80');
}

const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { return send(res, 400, 'Bad request'); }

  if (req.method === 'OPTIONS') return send(res, 204, '');
  if (url.pathname === '/' || url.pathname === '/health') {
    return send(res, 200, JSON.stringify({ ok: true, service: 'm26-stalker-relay' }), { 'content-type': 'application/json' });
  }
  if (url.pathname !== '/stalker-proxy') return send(res, 404, 'Not found');
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');

  const p = url.searchParams;
  const ep = p.get('ep') || '';
  const mac = p.get('mac') || '';
  const portalRaw = p.get('portal') || '';

  if (!ENDPOINTS.has(ep)) return send(res, 400, 'Invalid endpoint');
  if (!MAC_RE.test(mac)) return send(res, 400, 'Invalid MAC');
  let portal;
  try { portal = new URL(portalRaw); } catch { return send(res, 400, 'Invalid portal URL'); }
  if (portal.protocol !== 'http:' && portal.protocol !== 'https:') return send(res, 400, 'Invalid portal URL');
  if (isPrivateHost(portal.hostname)) return send(res, 400, 'Refused');

  const forward = new URLSearchParams(p);
  forward.delete('portal');
  forward.delete('ep');
  const target = new URL(portal.origin + '/' + ep);
  target.search = forward.toString();

  const token = p.get('token') || '';
  const headers = {
    'User-Agent': STB_UA,
    'Accept': '*/*',
    'Cookie': `mac=${mac}; stb_lang=en; timezone=Europe/London`,
    'X-User-Agent': 'Model: MAG250; Link: WiFi',
    'Referer': portal.origin + '/c/'
  };
  if (token) headers['Authorization'] = 'Bearer ' + token;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 20000);
  try {
    const upstream = await fetch(target.toString(), { method: 'GET', headers, redirect: 'follow', signal: ac.signal });
    const body = Buffer.from(await upstream.arrayBuffer());
    /* Pass the upstream status and body through untouched — the app distinguishes a portal auth
       refusal from a firewall block by reading them, so neither may be normalised away here. */
    send(res, upstream.status, body, { 'content-type': upstream.headers.get('content-type') || 'application/json' });
  } catch (e) {
    const aborted = e && (e.name === 'AbortError' || ac.signal.aborted);
    send(res, 502, JSON.stringify({ error: aborted ? 'portal_timeout' : 'portal_unreachable', detail: String((e && e.message) || e) }), { 'content-type': 'application/json' });
  } finally { clearTimeout(timer); }
});

server.listen(PORT, () => console.log('m26-stalker-relay listening on ' + PORT));
