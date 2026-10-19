/* Lock In — offline shell. App shell + puter.js cached; exercise demos (ExerciseDB / free-exercise-db)
   cached as you view them in a separate long-lived cache. Puter API calls always hit the network. */
const CACHE = 'lockin-v27';
const MEDIA_CACHE = 'lockin-media-v1';
const SHELL = ['./', './index.html', './exlib.json', './manifest.webmanifest'];
const ICONS = ['./icon-192.png', './icon-512.png', './apple-touch-icon.png'];
const PUTER = 'https://js.puter.com/v2/';
const MEDIA_HOSTS = ['static.exercisedb.dev', 'images.weserv.nl', 'raw.githubusercontent.com'];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await Promise.allSettled(SHELL.map(u => c.add(u)));
    await Promise.allSettled(ICONS.map(u => c.add(u)));
    try { await c.add(new Request(PUTER, { mode: 'no-cors' })); } catch (e) {}
    self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE && k !== MEDIA_CACHE).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  const isPuterJs = url.href.indexOf('https://js.puter.com/') === 0;
  const sameOrigin = url.origin === location.origin;
  const isMedia = MEDIA_HOSTS.includes(url.hostname) && (req.destination === 'image' || /\.(gif|jpg|png)(\?|$)/.test(url.pathname));

  if (isMedia) {
    e.respondWith(caches.open(MEDIA_CACHE).then(c => c.match(req).then(hit => hit || fetch(req).then(res => {
      if (res && (res.ok || res.type === 'opaque')) c.put(req, res.clone());
      return res;
    }))));
    return;
  }
  if (!sameOrigin && !isPuterJs) return;
  // friends API + avatars: always live (avatars have their own long-lived HTTP caching)
  if (sameOrigin && url.pathname.startsWith('/api/')) return;

  if (req.mode === 'navigate') {
    // only the app itself becomes the offline copy — never an invite / shared-split page
    const isApp = url.pathname === '/' || url.pathname === '/index.html';
    e.respondWith(
      fetch(req)
        .then(res => { if (isApp && res.ok) { const cl = res.clone(); caches.open(CACHE).then(c => c.put('./index.html', cl)); } return res; })
        .catch(() => caches.match('./index.html').then(r => r || caches.match('./')))
    );
    return;
  }
  // exlib.json: network-first so library updates arrive; everything else cache-first
  if (sameOrigin && url.pathname.endsWith('exlib.json')) {
    e.respondWith(fetch(req).then(res => { const cl = res.clone(); caches.open(CACHE).then(c => c.put(req, cl)); return res; }).catch(() => caches.match(req)));
    return;
  }
  e.respondWith(
    caches.match(req, { ignoreSearch: true }).then(hit =>
      hit || fetch(req).then(res => {
        if (res && (res.ok || res.type === 'opaque')) { const cl = res.clone(); caches.open(CACHE).then(c => c.put(req, cl)); }
        return res;
      }).catch(() => hit)
    )
  );
});
