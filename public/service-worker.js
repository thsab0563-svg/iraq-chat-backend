/* Iraq Chat - Service Worker v2.0 with Push */

const VERSION = 'v2.0.0';
const STATIC_CACHE = 'iraq-chat-static-' + VERSION;
const RUNTIME_CACHE = 'iraq-chat-runtime-' + VERSION;
const PRECACHE = ['/', '/manifest.json', '/icon.svg'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(STATIC_CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== STATIC_CACHE && k !== RUNTIME_CACHE).map(k => caches.delete(k)))
  ).then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/socket.io/') || url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/uploads/') || url.pathname === '/health' ||
      url.pathname === '/upload' || req.method !== 'GET') return;

  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    e.respondWith(fetch(req).then(res => {
      const c = res.clone();
      caches.open(RUNTIME_CACHE).then(cache => cache.put(req, c));
      return res;
    }).catch(() => caches.match(req).then(c => c || caches.match('/'))));
    return;
  }

  e.respondWith(caches.match(req).then(cached => {
    if (cached) return cached;
    return fetch(req).then(res => {
      if (res.ok && res.status === 200) {
        const c = res.clone();
        caches.open(RUNTIME_CACHE).then(cache => cache.put(req, c));
      }
      return res;
    }).catch(() => cached);
  }));
});

self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ===== PUSH NOTIFICATIONS ===== */
self.addEventListener('push', (event) => {
  if (!event.data) return;
  let data = {};
  try { data = event.data.json(); } catch (_) {
    data = { title: 'دردشة العراق', body: event.data.text() };
  }

  const title = data.title || 'دردشة العراق';
  const options = {
    body: data.body || '',
    icon: '/icon.svg',
    badge: '/icon.svg',
    dir: 'rtl',
    lang: 'ar',
    vibrate: [200, 100, 200],
    tag: data.tag || 'iraq-chat-' + Date.now(),
    renotify: true,
    requireInteraction: false,
    data: { url: data.url || '/', type: data.type || '' }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes(self.location.origin) && 'focus' in c) {
          c.focus();
          if ('navigate' in c) c.navigate(url);
          return;
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
