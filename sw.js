/* Media26 minimal service worker — required so the browser treats the page as an
   installable web app. Streams and API calls always go straight to the network;
   only the app shell files are cached for faster startup. */
const CACHE = 'media26-shell-v3';
/* Every entry must be a file that actually ships, and each is cached on its own:
   addAll() rejects the whole batch if a single file 404s, which used to leave the
   installed app with an empty shell cache. */
const SHELL = ['./', './index.html', './manifest.json', './icon-512.png', './apple-touch-icon.png', './watermark logo.png'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.all(SHELL.map(f => c.add(f).catch(() => {}))))
      .catch(() => {})
  );
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
    }).catch(() =>
      /* Offline: fall back to the cached copy, and for a navigation that was never
         cached (e.g. an old home-screen shortcut pointing at a removed page) fall
         back to the app shell rather than showing a blank page. */
      caches.match(e.request).then(hit =>
        hit || (e.request.mode === 'navigate' ? caches.match('./index.html') : undefined)
      )
    )
  );
});
