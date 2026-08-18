const TRANSCODER_ORIGIN = 'https://smarter-iptv-transcoder.onrender.com';

function withCors(headers) {
  const out = new Headers(headers);
  out.set('access-control-allow-origin', '*');
  out.set('access-control-allow-methods', 'GET,HEAD,POST,OPTIONS');
  out.set('access-control-allow-headers', 'accept,content-type,range,authorization,x-admin-key');
  out.set('access-control-expose-headers', 'content-length,content-range,accept-ranges,content-type,location');
  out.set('cross-origin-resource-policy', 'cross-origin');
  out.set('timing-allow-origin', '*');
  return out;
}

function rewriteLocation(location, requestUrl) {
  if (!location) return '';
  const current = new URL(requestUrl);
  try {
    const upstream = new URL(location, TRANSCODER_ORIGIN);
    if (upstream.origin === TRANSCODER_ORIGIN) {
      return `${current.origin}/transcoder${upstream.pathname}${upstream.search}`;
    }
  } catch {}
  if (location.startsWith('/')) return `${current.origin}/transcoder${location}`;
  return location;
}

/* Stalker/MAG/Ministra portal proxy. Browsers can't send the MAC-address cookie or the MAG
   set-top-box User-Agent these portals require to respond, and most send no CORS headers at
   all — so Stalker requests are relayed here, where those headers are set server-side. This is
   NOT an open "fetch any URL" proxy: only GET requests to a path ending in a Stalker loader
   script, on a portal host the caller supplies, are forwarded. */
/* v6.3: the endpoint is no longer a fixed list. A portal URL usually carries the folder the panel
   is installed in (…/c/, …/stalker_portal/, …/magportal/), and that folder used to be discarded
   here — the target was always built from portal.origin, so a correct portal URL with a path could
   never be reached and 404'd on every hardcoded candidate. The app now derives loader paths from
   the URL the user typed, so this has to accept a path it wasn't compiled with. It is still not an
   open proxy: the path must be a short chain of plain segments ending in the Stalker loader script
   itself, so nothing but portal.php / load.php can ever be requested through here. */
const STALKER_EP_RE = /^(?:[A-Za-z0-9._~-]{1,40}\/){0,4}(?:portal|load)\.php$/;
function validStalkerEndpoint(ep) {
  if (!STALKER_EP_RE.test(ep)) return false;
  return !ep.split('/').some(s => s === '.' || s === '..');
}
// Loader folder, used as the Referer the portal expects ('/c/' when it sits at the root).
function stalkerReferer(origin, ep) {
  const i = ep.lastIndexOf('/');
  return origin + '/' + (i < 0 ? 'c/' : ep.slice(0, i + 1));
}
const STALKER_UA = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';

async function handleStalkerProxy(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: withCors(new Headers()) });
  }
  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405, headers: withCors(new Headers()) });
  }

  const params = new URL(request.url).searchParams;
  const portalRaw = params.get('portal') || '';
  const ep = params.get('ep') || '';
  const mac = params.get('mac') || '';

  if (!validStalkerEndpoint(ep)) {
    return new Response('Invalid endpoint', { status: 400, headers: withCors(new Headers()) });
  }
  if (!/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/.test(mac)) {
    return new Response('Invalid MAC', { status: 400, headers: withCors(new Headers()) });
  }
  let portal;
  try {
    portal = new URL(portalRaw);
  } catch {
    return new Response('Invalid portal URL', { status: 400, headers: withCors(new Headers()) });
  }
  if (portal.protocol !== 'http:' && portal.protocol !== 'https:') {
    return new Response('Invalid portal URL', { status: 400, headers: withCors(new Headers()) });
  }
  // Same SSRF guard the other two relay builds carry: a caller-supplied portal host must never be
  // usable to probe a private network from here.
  if (isPrivateHost(portal.hostname)) {
    return new Response('Refused', { status: 400, headers: withCors(new Headers()) });
  }

  const forward = new URLSearchParams(params);
  forward.delete('portal');
  forward.delete('ep');
  const target = new URL(portal.origin + '/' + ep);
  target.search = forward.toString();

  const token = params.get('token') || '';
  const headers = new Headers({
    'User-Agent': STALKER_UA,
    'Accept': '*/*',
    'Cookie': `mac=${mac}; stb_lang=en; timezone=Europe/London`,
    'X-User-Agent': 'Model: MAG250; Link: WiFi',
    'Referer': stalkerReferer(portal.origin, ep)
  });
  if (token) headers.set('Authorization', 'Bearer ' + token);

  try {
    const upstream = await fetch(target.toString(), { method: 'GET', headers, redirect: 'follow' });
    const respHeaders = withCors(new Headers({ 'content-type': upstream.headers.get('content-type') || 'application/json' }));
    return new Response(upstream.body, { status: upstream.status, headers: respHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'stalker_upstream_unreachable' }), { status: 502, headers: withCors(new Headers({ 'content-type': 'application/json' })) });
  }
}

/* Generic same-origin CORS relay for arbitrary Xtream API calls and stream URLs the browser
   can't fetch directly — either the target sends no CORS headers at all (typical Xtream panel),
   or it's plain http:// being fetched from this https:// page (mixed content, blocked outright).
   index.html references this at /proxy?url=<target>[&dl=1&name=...] (see PROXY/SAME_ORIGIN_PROXY)
   but no route ever implemented it, so every request silently fell through to env.ASSETS.fetch
   and got back index.html itself instead of the proxied content — that's what was actually
   breaking Xtream login and every Stalker HLS stream (the .m3u8 "content" was literally this
   app's own HTML). Unlike /stalker-proxy this can't be restricted to a fixed set of paths, since
   portals and stream URLs are inherently caller-supplied and dynamic; the only guard available is
   refusing private/loopback network targets so this can't be turned into an SSRF probe of
   internal infrastructure. */
function isPrivateHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '0.0.0.0') return true;
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const a = parseInt(ipv4[1], 10), b = parseInt(ipv4[2], 10);
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  return false;
}

/* v7.0: an HLS playlist cannot be passed through untouched. Its segment and variant URLs are
   either relative — and the browser resolves those against THIS proxy URL, producing
   https://<app>/123.ts, a 404 — or absolute http://, which an https page refuses outright as mixed
   content. Either way the playlist loads and playback then dies. Rewrite every URL it contains so
   the whole ladder (variants, segments, keys, init sections) comes back through here too. */
function rewriteHlsPlaylist(text, playlistUrl, proxyPrefix) {
  let base;
  try { base = new URL(playlistUrl); } catch { return text; }
  const wrap = u => {
    const t = String(u || '').trim();
    if (!t || t.startsWith('#')) return u;
    let abs;
    try { abs = new URL(t, base).toString(); } catch { return u; }
    return proxyPrefix + encodeURIComponent(abs);
  };
  return text.split('\n').map(line => {
    const t = line.trim();
    if (!t) return line;
    // Tag lines carry their URLs in a URI="..." attribute (EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA).
    if (t.startsWith('#')) return line.replace(/URI="([^"]*)"/g, (m, u) => 'URI="' + wrap(u) + '"');
    return wrap(t);
  }).join('\n');
}

/* Cloudflare Workers may only open outbound connections on this fixed set of ports. IPTV streams
   are routinely published on others (25461, 8000, 1935 ...), and a fetch to one of those fails
   here no matter how healthy the origin is — which surfaces in the player as a bare
   manifestLoadError. Name it, because the fix is a relay (see relay/), not the portal. */
const CF_FETCHABLE_PORTS = new Set([80, 8080, 8880, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443]);
function targetPort(u) { return u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80); }

async function handleGenericProxy(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: withCors(new Headers()) });
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method not allowed', { status: 405, headers: withCors(new Headers()) });
  }

  const params = new URL(request.url).searchParams;
  const targetRaw = params.get('url') || '';
  let target;
  try {
    target = new URL(targetRaw);
  } catch {
    return new Response('Invalid url', { status: 400, headers: withCors(new Headers()) });
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return new Response('Invalid url', { status: 400, headers: withCors(new Headers()) });
  }
  if (isPrivateHost(target.hostname)) {
    return new Response('Refused', { status: 400, headers: withCors(new Headers()) });
  }

  /* v7.2: a Stalker stream link is issued TO a set-top box — the portal saw a MAG user-agent and a
     mac cookie when it created the link, and many Ministra/Stalker setups check the same identity
     again when the stream itself is fetched. This relay was sending a desktop Chrome user-agent and
     no cookie, so the origin answered 403 on a link it had just issued. Carry the STB identity
     through when the caller asks for it (ua=stb&mac=...). */
  const wantStb = params.get('ua') === 'stb';
  const stbMac = params.get('mac') || '';
  const headers = new Headers({
    'User-Agent': wantStb ? STALKER_UA : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': '*/*'
  });
  if (wantStb) {
    if (/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/.test(stbMac)) headers.set('Cookie', `mac=${stbMac}; stb_lang=en; timezone=Europe/London`);
    headers.set('X-User-Agent', 'Model: MAG250; Link: WiFi');
    headers.set('Referer', target.origin + '/c/');
  }
  const range = request.headers.get('range');
  if (range) headers.set('Range', range);

  const port = targetPort(target);
  if (!CF_FETCHABLE_PORTS.has(port)) {
    return new Response(JSON.stringify({ error: 'port_not_fetchable', port, detail: 'This host cannot open outbound connections on port ' + port + '. Use a relay (see relay/) for streams on this port.' }),
      { status: 502, headers: withCors(new Headers({ 'content-type': 'application/json', 'x-m26-reason': 'port-' + port })) });
  }

  let upstream;
  try {
    upstream = await fetch(target.toString(), { method: request.method, headers, redirect: 'follow' });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'upstream_unreachable', detail: String((e && e.message) || e) }), { status: 502, headers: withCors(new Headers({ 'content-type': 'application/json' })) });
  }

  // Playlists are small text; rewrite them. Everything else streams through untouched.
  const ctype = upstream.headers.get('content-type') || '';
  const looksHls = /mpegurl|x-mpegURL/i.test(ctype) || /\.m3u8(\?|$)/i.test(target.pathname + target.search);
  if (request.method === 'GET' && !range && upstream.ok && looksHls) {
    const text = await upstream.text();
    if (/^\s*#EXTM3U/.test(text)) {
      const proxyPrefix = new URL(request.url).origin + '/proxy?url=';
      const out = rewriteHlsPlaylist(text, upstream.url || target.toString(), proxyPrefix);
      return new Response(out, { status: 200, headers: withCors(new Headers({ 'content-type': 'application/vnd.apple.mpegurl' })) });
    }
    return new Response(text, { status: upstream.status, headers: withCors(upstream.headers) });
  }

  // v7.0: many cheap Xtream/IPTV origins don't implement HTTP Range at all — they ignore the
  // Range header and answer with a plain 200 (the whole file) no matter what was asked. A
  // <video> element that requested a range and gets back an unranged 200 treats it as a brand
  // new resource: playback position snaps to 0 and the movie looks like it "restarted" the
  // instant someone taps forward. Detect exactly that (client sent Range, origin answered 200)
  // and fake a real 206 ourselves by skipping the requested number of bytes out of the body we
  // already have — the seek still has to wait for those bytes to arrive, but the browser sees a
  // correct partial response and keeps playing from the right spot instead of jumping back.
  if (range && request.method === 'GET' && upstream.status === 200 && upstream.body) {
    const total = Number(upstream.headers.get('content-length'));
    const m = /^bytes=(\d+)-(\d*)$/.exec(range.trim());
    if (m && Number.isFinite(total) && total > 0) {
      const start = Number(m[1]);
      const end = m[2] ? Math.min(Number(m[2]), total - 1) : total - 1;
      if (start >= 0 && start < total && end >= start) {
        const respHeaders = withCors(upstream.headers);
        respHeaders.set('content-range', `bytes ${start}-${end}/${total}`);
        respHeaders.set('content-length', String(end - start + 1));
        respHeaders.set('accept-ranges', 'bytes');
        if (params.get('dl') === '1') {
          const name = (params.get('name') || 'download').replace(/"/g, '');
          respHeaders.set('content-disposition', `attachment; filename="${name}"`);
        }
        return new Response(skipBytes(upstream.body, start, end - start + 1), { status: 206, statusText: 'Partial Content', headers: respHeaders });
      }
    }
  }

  const respHeaders = withCors(upstream.headers);
  if (params.get('dl') === '1') {
    const name = (params.get('name') || 'download').replace(/"/g, '');
    respHeaders.set('content-disposition', `attachment; filename="${name}"`);
  }
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: respHeaders });
}

// Reads `body`, drops the first `skip` bytes, and yields at most `take` bytes after that —
// turns an origin's unranged 200 into the exact slice a real 206 would have sent.
function skipBytes(body, skip, take) {
  const reader = body.getReader();
  let skipped = 0, sent = 0, closed = false;
  return new ReadableStream({
    async pull(controller) {
      if (closed) { controller.close(); return; }
      while (true) {
        const { done, value } = await reader.read();
        if (done) { closed = true; controller.close(); return; }
        let chunk = value;
        if (skipped < skip) {
          const need = skip - skipped;
          if (chunk.byteLength <= need) { skipped += chunk.byteLength; continue; }
          chunk = chunk.subarray(need);
          skipped = skip;
        }
        if (sent + chunk.byteLength >= take) {
          chunk = chunk.subarray(0, take - sent);
          sent += chunk.byteLength;
          controller.enqueue(chunk);
          closed = true;
          try { reader.cancel(); } catch {}
          controller.close();
          return;
        }
        sent += chunk.byteLength;
        controller.enqueue(chunk);
        return;
      }
    },
    cancel() { try { reader.cancel(); } catch {} }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/stalker-proxy') {
      return handleStalkerProxy(request);
    }

    if (url.pathname === '/proxy') {
      return handleGenericProxy(request);
    }

    /* v6.4: the web app manifest used to declare start_url "./media26.html" — a file this app has
       never contained. Every home-screen icon installed from it therefore launches a URL that 404s,
       which is the blank white screen people get when they open the saved app. The manifest now
       points at index.html, but an icon already sitting on someone's phone keeps the start_url it
       was installed with, so serve the app at the old path too instead of leaving those installs
       permanently broken. */
    if (url.pathname === '/media26.html') {
      return env.ASSETS.fetch(new Request(new URL('/index.html', url).toString(), request));
    }

    if (!url.pathname.startsWith('/transcoder/')) {
      return env.ASSETS.fetch(request);
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: withCors(new Headers()) });
    }

    const upstreamPath = url.pathname.replace(/^\/transcoder/, '') || '/';
    const upstreamUrl = new URL(upstreamPath + url.search, TRANSCODER_ORIGIN);
    const headers = new Headers(request.headers);
    headers.delete('host');

    const upstreamResponse = await fetch(upstreamUrl, {
      method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
      redirect: 'manual'
    });

    const responseHeaders = withCors(upstreamResponse.headers);
    const location = rewriteLocation(responseHeaders.get('location'), request.url);
    if (location) responseHeaders.set('location', location);

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders
    });
  }
};
