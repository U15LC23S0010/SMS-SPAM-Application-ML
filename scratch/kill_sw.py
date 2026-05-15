import os

templates_dir = 'templates'
unreg_script = """
    <script>
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.getRegistrations().then(function(registrations) {
                for(let registration of registrations) {
                    registration.unregister().then(function() { console.log('SW unregistered'); });
                }
            });
        }
    </script>
"""

for filename in ['login.html', 'index.html', 'register.html']:
    filepath = os.path.join(templates_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        if 'unregister()' not in content:
            content = content.replace('</body>', unreg_script + '</body>')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("Unregistration script injected.")
