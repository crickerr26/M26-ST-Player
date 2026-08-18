/* M26 Stalker relay — a standalone copy of the /stalker-proxy route from _worker.js, meant to run
   somewhere that is NOT Cloudflare.

   Why this exists: the player is deployed on Cloudflare Workers, and the IPTV portals it talks to
   sit behind Cloudflare too. Portal calls therefore reach the origin from Cloudflare's own network
   carrying the MAG set-top-box User-Agent the Stalker protocol requires — which can read as a bot
   and draw a challenge, and a challenge answers with an HTML page instead of JSON. Running the
   relay on an ordinary host (Render, Fly, a VPS) makes the request arrive from a normal datacenter
   IP instead, sidestepping the Cloudflare-to-Cloudflare path entirely.

   Deliberately NOT an open proxy: only GET, only the known set of Stalker loader scripts,
   only a syntactically valid MAC, and never to a private/loopback address. Same guards as the
   Worker version. Only the small JSON API calls belong here — video segments keep using whatever
   path the app already uses, so a free instance is not asked to push streams.

   No dependencies; Node 18+ (global fetch). Start: node server.js  (PORT from env, default 8080) */
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ENDPOINTS = new Set(['portal.php', 'stalker_portal/server/load.php', 'server/load.php', 'c/portal.php', 'stalker_portal/portal.php', 'magportal/portal.php', 'p/portal.php', 'k/portal.php']);
const STB_UA = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';
const MAC_RE = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;
const PORT = Number(process.env.PORT) || 8080;
const APP_ROOT = path.resolve(__dirname, '..');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json; charset=utf-8'
};

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
function proxySelf(req, target) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  const here = new URL(req.url, `${proto}://${host}`);
  const extra = ['portal', 'mac', 'token'].map(k => {
    const v = here.searchParams.get(k);
    return v ? `&${k}=${encodeURIComponent(v)}` : '';
  }).join('');
  return `${proto}://${host}/proxy?url=${encodeURIComponent(target)}${extra}`;
}
function isPlaylist(target, headers) {
  const ct = String(headers.get('content-type') || '').toLowerCase();
  return /mpegurl|m3u8/.test(ct) || /\.m3u8(?:$|[?#])/i.test(target.pathname);
}
function rewritePlaylist(text, baseUrl, mkProxy) {
  const absolutize = (raw) => {
    const v = String(raw || '').trim();
    if (!v || /^(data|blob|javascript):/i.test(v)) return raw;
    try { return mkProxy(new URL(v, baseUrl).toString()); } catch { return raw; }
  };
  return String(text || '').split(/\r?\n/).map((line) => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    if (trimmed[0] !== '#') return absolutize(trimmed);
    return line.replace(/URI="([^"]+)"/g, (_, u) => `URI="${absolutize(u)}"`);
  }).join('\n');
}
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  const requested = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const file = path.resolve(APP_ROOT, requested.replace(/^\/+/, ''));
  if (!file.startsWith(APP_ROOT + path.sep)) return send(res, 403, 'Refused');
  fs.stat(file, (err, stat) => {
    if (err || !stat.isFile()) return send(res, 404, 'Not found');
    const headers = cors({
      'content-type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'content-length': stat.size,
      'cache-control': 'no-store'
    });
    res.writeHead(200, headers);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
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
  const mac = p.get('mac') || '';
  const portalRaw = p.get('portal') || '';
  if (mac || portalRaw) {
    let portal;
    try { portal = new URL(portalRaw); } catch { return send(res, 400, 'Invalid portal URL'); }
    if (portal.protocol !== 'http:' && portal.protocol !== 'https:') return send(res, 400, 'Invalid portal URL');
    if (isPrivateHost(portal.hostname)) return send(res, 400, 'Refused');
    if (!MAC_RE.test(mac)) return send(res, 400, 'Invalid MAC');
    headers['User-Agent'] = STB_UA;
    headers['Cookie'] = `mac=${mac}; stb_lang=en; timezone=Europe/London`;
    headers['X-User-Agent'] = 'Model: MAG250; Link: WiFi';
    headers['Referer'] = portal.origin + '/c/';
    const token = p.get('token') || '';
    if (token) headers['Authorization'] = 'Bearer ' + token;
  }
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

  if (req.method === 'GET' && upstream.body && isPlaylist(target, upstream.headers)) {
    const text = await upstream.text();
    if (!/^\s*#EXTM3U/i.test(text)) {
      delete out['content-length'];
      return send(res, upstream.status, text, out);
    }
    const body = rewritePlaylist(text, target.toString(), u => proxySelf(req, u));
    delete out['content-length'];
    out['content-type'] = 'application/vnd.apple.mpegurl; charset=utf-8';
    out['cache-control'] = 'no-store';
    return send(res, upstream.status, body, out);
  }

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
  if (url.pathname === '/health') {
    return send(res, 200, JSON.stringify({ ok: true, service: 'm26-stalker-relay', routes: ['/stalker-proxy', '/proxy'] }), { 'content-type': 'application/json' });
  }
  if (url.pathname === '/proxy') return handleStreamProxy(req, res, url).catch(() => { try { res.end(); } catch {} });
  if (url.pathname !== '/stalker-proxy') return serveStatic(req, res, url);
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
