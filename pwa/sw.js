// mes Network PWA service worker — offline shell + Web Push handler
const CACHE = 'mes-pwa-v39-real-flow-bytes-today-stat';
const ASSETS = [
  '/pwa/',
  '/pwa/index.html',
  '/pwa/manifest.json',
  '/pwa/icon.svg',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).catch(()=>{}));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

// Web Push handler — show a system notification when a push arrives
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = { title: 'mes Network', body: event.data ? event.data.text() : '' }; }
  const title = data.title || 'mes Network';
  const opts = {
    body: data.body || '',
    icon: '/pwa/icon.svg',
    badge: '/pwa/icon.svg',
    data: { url: data.url || '/pwa/' },
    tag: data.kind || 'mes-push',
  };
  event.waitUntil(self.registration.showNotification(title, opts));
});

// When user taps the notification, open/focus the PWA
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url || '/pwa/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // API calls always hit the network (don't cache responses — they're dynamic + auth-bound)
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/admin/')) {
    e.respondWith(
      fetch(e.request).catch(() =>
        new Response(JSON.stringify({ error: 'offline', offline: true }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    );
    return;
  }

  // For static shell assets — network first, fall back to cache
  e.respondWith(
    fetch(e.request)
      .then(res => {
        // Update cache on every successful fetch (so the shell stays fresh)
        if (res.ok && (url.pathname === '/pwa/' || url.pathname.startsWith('/pwa/'))) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request).then(c => c || caches.match('/pwa/index.html')))
  );
});
