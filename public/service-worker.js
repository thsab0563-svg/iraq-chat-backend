/* Iraq Chat - Service Worker v1.0 */

const VERSION = 'v1.0.0';
const STATIC_CACHE = 'iraq-chat-static-' + VERSION;
const RUNTIME_CACHE = 'iraq-chat-runtime-' + VERSION;

const PRECACHE = [
  '/',
  '/manifest.json',
  '/icon.svg'
];

// ===== Install =====
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

// ===== Activate =====
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k !== STATIC_CACHE && k !== RUNTIME_CACHE)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ===== Fetch strategy =====
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle same-origin
  if (url.origin !== self.location.origin) return;

  // Skip: socket.io, API, uploads, health, POST
  if (
    url.pathname.startsWith('/socket.io/') ||
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/uploads/') ||
    url.pathname === '/health' ||
    url.pathname === '/upload' ||
    req.method !== 'GET'
  ) return;

  // HTML → network-first (تحصل التحديثات)
  if (req.mode === 'navigate' || req.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(RUNTIME_CACHE).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req).then((c) => c || caches.match('/')))
    );
    return;
  }

  // CSS/JS/Assets → cache-first
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        if (res.ok && res.status === 200) {
          const copy = res.clone();
          caches.open(RUNTIME_CACHE).then((c) => c.put(req, copy));
        }
        return res;
      }).catch(() => cached);
    })
  );
});

// ===== Messages from app =====
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ===== Push Notifications (جاهز للمرحلة القادمة) =====
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
    tag: data.tag || 'iraq-chat',
    renotify: true,
    data: { url: data.url || '/' }
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
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
