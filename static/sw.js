const CACHE_NAME = 'guardian-v5';
const STATIC_ASSETS = [
    '/static/style.css',
    '/static/script.js',
    '/static/pwa.js',
    '/manifest.json',
    '/static/icon-192x192.png',
    '/static/icon-512x512.png'
];

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            console.log('SW: Pre-caching assets');
            // Use individual add for each to avoid failure of whole cache if one missing
            return Promise.allSettled(
                STATIC_ASSETS.map(url => cache.add(url).catch(err => console.log('Failed to cache:', url, err)))
            );
        })
    );
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
        ))
    );
    self.clients.claim();
});

self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;
    
    // Performance optimization: check if it's a static asset
    const url = new URL(event.request.url);
    const isStatic = STATIC_ASSETS.some(asset => url.pathname === asset);

    if (isStatic) {
        event.respondWith(
            caches.match(event.request).then(resp => resp || fetch(event.request))
        );
    } else {
        // Network-first for everything else to ensure admin actions/scans work
        event.respondWith(
            fetch(event.request).catch(() => caches.match(event.request))
        );
    }
});
