const CACHE = "dv-wallet-v1";
const FILES = [
  "./",
  "./index.html",
  "./manifest.json",
  "./qrcode.min.js"
];

self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(FILES))
  );
});

self.addEventListener("fetch", e => {
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});
