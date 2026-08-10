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
   NOT an open "fetch any URL" proxy: only GET requests to one of a fixed set of known Stalker
   loader scripts, on a portal host the caller supplies, are forwarded. */
const STALKER_ENDPOINTS = new Set(['portal.php', 'stalker_portal/server/load.php', 'server/load.php', 'c/portal.php']);
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

  if (!STALKER_ENDPOINTS.has(ep)) {
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
    'Referer': portal.origin + '/c/'
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

  const headers = new Headers({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': '*/*'
  });
  const range = request.headers.get('range');
  if (range) headers.set('Range', range);

  let upstream;
  try {
    upstream = await fetch(target.toString(), { method: request.method, headers, redirect: 'follow' });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'upstream_unreachable' }), { status: 502, headers: withCors(new Headers({ 'content-type': 'application/json' })) });
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
