self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = { title: 'Anonomoose', body: 'New sealed note', kind: 'note' };
  try {
    if (event.data) data = Object.assign(data, event.data.json());
  } catch (e) {}
  const call = data.kind === 'call';
  event.waitUntil(self.registration.showNotification(data.title || 'Anonomoose', {
    body: data.body || 'New sealed note',
    tag: data.tag || ('moose-' + (data.kind || 'note')),
    renotify: true,
    silent: false,
    vibrate: call ? [400, 200, 400, 200, 400] : [200, 100, 200],
    data: { url: '/' }
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if (c.url && 'focus' in c) return c.focus();
    }
    if (self.clients.openWindow) return self.clients.openWindow('/');
  })());
});
