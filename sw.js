/* Media26 minimal service worker — required so the browser treats the page as an
   installable web app. Streams and API calls always go straight to the network;
   only the app shell files are cached for faster startup. */
const CACHE = 'media26-shell-v3';
/* v6.4: this list used to name ./media26.html and ./icon-192.png — neither of which exists in this
   app. addAll() is atomic, so ONE missing file threw away the whole precache and the shell was
   never stored at all. Name the files that are really here, and store them one by one so a future
   rename degrades to "that one file isn't cached" instead of "nothing is". */
const SHELL = ['./', './index.html', './manifest.json', './icon-512.png', './apple-touch-icon.png', './watermark logo.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c =>
    Promise.all(SHELL.map(u => c.add(u).catch(() => {})))
  ).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

/* Never cache these: the portal API (a stale handshake/profile reply is worse than no reply) and
   the stream and transcoder relays, whose responses are video — minutes of live TV would otherwise
   pile up in Cache Storage until the browser evicts the app shell to make room. The old handler
   said "only shell files" in a comment but actually cached every same-origin GET, these included. */
const NEVER_CACHE = /^\/(stalker-proxy|proxy|transcoder)(\/|$|\?)/;

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (NEVER_CACHE.test(url.pathname)) return;

  e.respondWith(
    fetch(e.request).then(r => {
      // Only a real, complete same-origin response is worth keeping (not a 404, not an opaque one).
      if (r && r.ok && r.type === 'basic') {
        const copy = r.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
      }
      return r;
    }).catch(async () => {
      /* Offline. A miss used to resolve as undefined, which respondWith turns into a network error
         — the app launching to a blank white screen. Fall back to the cached shell for navigations
         so opening the home-screen icon always lands on the app itself. */
      const hit = await caches.match(e.request);
      if (hit) return hit;
      if (e.request.mode === 'navigate') {
        const shell = await caches.match('./index.html') || await caches.match('./');
        if (shell) return shell;
      }
      return new Response('Offline', { status: 503, headers: { 'content-type': 'text/plain' } });
    })
  );
});
