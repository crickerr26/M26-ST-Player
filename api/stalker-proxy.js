/* Serverless build of the Stalker portal relay — same contract as relay/server.js and the
   /stalker-proxy route in _worker.js, packaged for hosts that deploy this repo directly
   (Vercel and anything else that serves an api/ directory as functions).
     - On Vercel this is reachable at /api/stalker-proxy, and vercel.json rewrites /stalker-proxy
       onto it so the URL matches the other two builds.
     - If the whole app is deployed here, the app's default same-origin route already points at
       it and no relay URL needs configuring at all.

   Exists because the app normally runs on Cloudflare Workers while the portals themselves sit
   behind Cloudflare, so portal calls arrive from Cloudflare's own network carrying the MAG
   set-top-box User-Agent the Stalker protocol requires — which can draw a bot challenge that
   answers with HTML instead of JSON. Serving from somewhere else avoids that path.

   Deliberately not an open proxy: GET only, the four known Stalker loader scripts only, a valid
   MAC required, and private/loopback/link-local/metadata targets refused. */
'use strict';

const ENDPOINTS = new Set(['portal.php', 'stalker_portal/server/load.php', 'server/load.php', 'c/portal.php']);
const STB_UA = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';
const MAC_RE = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

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

function cors(res) {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET,HEAD,OPTIONS');
  res.setHeader('access-control-allow-headers', 'accept,content-type,range,authorization');
  res.setHeader('cross-origin-resource-policy', 'cross-origin');
  res.setHeader('timing-allow-origin', '*');
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET' && req.method !== 'HEAD') return res.status(405).send('Method not allowed');

  const q = req.query || {};
  const first = v => (Array.isArray(v) ? v[0] : v) || '';
  const ep = first(q.ep), mac = first(q.mac), portalRaw = first(q.portal);

  if (!ENDPOINTS.has(ep)) return res.status(400).send('Invalid endpoint');
  if (!MAC_RE.test(mac)) return res.status(400).send('Invalid MAC');
  let portal;
  try { portal = new URL(portalRaw); } catch { return res.status(400).send('Invalid portal URL'); }
  if (portal.protocol !== 'http:' && portal.protocol !== 'https:') return res.status(400).send('Invalid portal URL');
  if (isPrivateHost(portal.hostname)) return res.status(400).send('Refused');

  const forward = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (k === 'portal' || k === 'ep') continue;
    forward.set(k, first(v));
  }
  const target = new URL(portal.origin + '/' + ep);
  target.search = forward.toString();

  const token = first(q.token);
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
    /* Pass the upstream status and body through untouched — the app tells a portal auth refusal
       apart from a firewall block by reading them, so neither may be normalised away here. */
    res.setHeader('content-type', upstream.headers.get('content-type') || 'application/json');
    return res.status(upstream.status).send(body);
  } catch (e) {
    const aborted = e && (e.name === 'AbortError' || ac.signal.aborted);
    res.setHeader('content-type', 'application/json');
    return res.status(502).send(JSON.stringify({ error: aborted ? 'portal_timeout' : 'portal_unreachable', detail: String((e && e.message) || e) }));
  } finally { clearTimeout(timer); }
};
