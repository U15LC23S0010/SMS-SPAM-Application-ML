let deferredPrompt;
const installBtn = document.getElementById('pwa-install-btn');

if (installBtn) {
    const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
    
    if (isStandalone) {
        installBtn.style.display = 'none';
    } else {
        installBtn.style.display = 'inline-flex';
    }

    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        installBtn.style.display = 'inline-flex';
        console.log('PWA: Ready to install');
    });

    installBtn.addEventListener('click', async (e) => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            const { outcome } = await deferredPrompt.userChoice;
            if (outcome === 'accepted') {
                installBtn.style.display = 'none';
            }
            deferredPrompt = null;
        } else {
            // Fallback instruction
            const msg = "To install Message Guardian:\n\n1. Open your browser menu (⋮ or )\n2. Tap 'Add to Home Screen' or 'Install App'.";
            alert(msg);
            
            // Try to force re-register if not working
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.getRegistrations().then(registrations => {
                    for(let registration of registrations) {
                        registration.update();
                    }
                });
            }
        }
    });

    window.addEventListener('appinstalled', (evt) => {
        installBtn.style.display = 'none';
    });
}

if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js', { scope: '/' })
            .then(reg => {
                // Ensure the update is checked
                reg.update();
            })
            .catch(err => console.error('SW Error:', err));
    });
}
