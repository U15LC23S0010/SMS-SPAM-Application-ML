import os
import re

templates_dir = 'templates'
manifest_link = '    <link rel="manifest" href="/manifest.json">\n'
sw_script = """
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/sw.js')
                    .then(reg => console.log('SW registered'))
                    .catch(err => console.log('SW failed', err));
            });
        }
    </script>
"""

for filename in os.listdir(templates_dir):
    if filename.endswith('.html'):
        filepath = os.path.join(templates_dir, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Add manifest
        if 'manifest.json' not in content:
            content = content.replace('</head>', manifest_link + '</head>')
        
        # Add SW registration
        if 'sw.js' not in content:
            content = content.replace('</body>', sw_script + '</body>')
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("PWA tags added to all templates.")
