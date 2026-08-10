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

/* Generic stream relay — the /proxy route from _worker.js. Portals serve streams over plain http
   with no CORS headers, so an https page can neither fetch them directly (mixed content) nor read
   them cross-origin; every segment has to come through here. Kept out of the serverless build on
   purpose: those cap out around a minute and a live channel runs for hours. On a VPS there is no
   such limit, which is what lets one box carry portal API, streams and transcoding together.

   Unlike /stalker-proxy this cannot be restricted to a fixed set of paths — stream URLs are
   whatever the portal hands back — so the guard is refusing private/loopback/metadata targets. */
async function handleStreamProxy(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  const p = url.searchParams;
  let target;
  try { target = new URL(p.get('url') || ''); } catch { return send(res, 400, 'Invalid url'); }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') return send(res, 400, 'Invalid url');
  if (isPrivateHost(target.hostname)) return send(res, 400, 'Refused');

  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': '*/*'
  };
  const range = req.headers['range'];
  if (range) headers['Range'] = range;

  let upstream;
  try {
    upstream = await fetch(target.toString(), { method: req.method, headers, redirect: 'follow' });
  } catch (e) {
    return send(res, 502, JSON.stringify({ error: 'upstream_unreachable', detail: String((e && e.message) || e) }), { 'content-type': 'application/json' });
  }

  const out = {};
  for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) {
    const v = upstream.headers.get(k);
    if (v) out[k] = v;
  }
  if (p.get('dl') === '1') out['content-disposition'] = `attachment; filename="${String(p.get('name') || 'download').replace(/"/g, '')}"`;

  /* Many cheap IPTV origins ignore Range entirely and answer 200 with the whole file. A <video>
     that asked for a range and gets an unranged 200 treats it as a new resource and snaps back to
     the start — which is the "movie restarts when you seek" bug. Detect exactly that and build the
     206 ourselves by skipping the requested bytes out of the body we are already receiving. */
  const total = Number(upstream.headers.get('content-length'));
  const m = /^bytes=(\d+)-(\d*)$/.exec(String(range || '').trim());
  if (range && req.method === 'GET' && upstream.status === 200 && upstream.body && m && Number.isFinite(total) && total > 0) {
    const start = Number(m[1]);
    const end = m[2] ? Math.min(Number(m[2]), total - 1) : total - 1;
    if (start >= 0 && start < total && end >= start) {
      out['content-range'] = `bytes ${start}-${end}/${total}`;
      out['content-length'] = String(end - start + 1);
      out['accept-ranges'] = 'bytes';
      res.writeHead(206, cors(out));
      let skipped = 0, sent = 0;
      const take = end - start + 1;
      for await (const chunk of upstream.body) {
        let buf = Buffer.from(chunk);
        if (skipped < start) {
          const need = start - skipped;
          if (buf.length <= need) { skipped += buf.length; continue; }
          buf = buf.subarray(need); skipped = start;
        }
        if (sent + buf.length >= take) { res.end(buf.subarray(0, take - sent)); return; }
        sent += buf.length;
        if (!res.write(buf)) await new Promise(r => res.once('drain', r));
      }
      return res.end();
    }
  }

  res.writeHead(upstream.status, cors(out));
  if (req.method === 'HEAD' || !upstream.body) return res.end();
  try {
    for await (const chunk of upstream.body) {
      if (!res.write(Buffer.from(chunk))) await new Promise(r => res.once('drain', r));
    }
  } catch { /* client went away mid-stream — normal when switching channels */ }
  res.end();
}

const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { return send(res, 400, 'Bad request'); }

  if (req.method === 'OPTIONS') return send(res, 204, '');
  if (url.pathname === '/' || url.pathname === '/health') {
    return send(res, 200, JSON.stringify({ ok: true, service: 'm26-stalker-relay', routes: ['/stalker-proxy', '/proxy'] }), { 'content-type': 'application/json' });
  }
  if (url.pathname === '/proxy') return handleStreamProxy(req, res, url).catch(() => { try { res.end(); } catch {} });
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
