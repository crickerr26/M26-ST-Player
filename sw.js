/* Media26 minimal service worker — required so the browser treats the page as an
   installable web app. Streams and API calls always go straight to the network;
   only the app shell files are cached for faster startup. */
const CACHE = 'media26-shell-v2';
const SHELL = ['./media26.html', './manifest.json', './icon-192.png', './icon-512.png', './watermark logo.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Only serve same-origin shell files from cache; everything else (streams, playlists, APIs) hits the network.
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  e.respondWith(
    fetch(e.request).then(r => {
      const copy = r.clone();
      caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
      return r;
    }).catch(() => caches.match(e.request))
  );
});
