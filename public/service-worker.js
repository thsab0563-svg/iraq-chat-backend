/* Iraq Chat SW v3.0 — aggressive update */
const VERSION = 'v3.0.0';
const CACHE = 'iraq-chat-' + VERSION;

self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// شبكة أولاً دائماً — لا cache للـ HTML
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.method !== 'GET') return;
  if (url.pathname.startsWith('/socket.io/') ||
      url.pathname.startsWith('/api/') ||
      url.pathname === '/health' ||
      url.pathname === '/upload') return;
  e.respondWith(fetch(req).catch(() => caches.match(req)));
});

self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

// Push
self.addEventListener('push', (event) => {
  if (!event.data) return;
  let data = {};
  try { data = event.data.json(); } catch (_) {
    data = { title: 'دردشة العراق', body: event.data.text() };
  }
  event.waitUntil(self.registration.showNotification(data.title || 'دردشة العراق', {
    body: data.body || '',
    icon: '/icon.svg',
    badge: '/icon.svg',
    dir: 'rtl',
    lang: 'ar',
    vibrate: [200, 100, 200],
    tag: data.tag || 'iraq-chat-' + Date.now(),
    renotify: true,
    data: { url: data.url || '/' }
  }));
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
