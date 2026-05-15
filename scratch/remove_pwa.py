import os
import re

templates_dir = 'templates'

for filename in os.listdir(templates_dir):
    if filename.endswith('.html'):
        filepath = os.path.join(templates_dir, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove SW registration script
        content = re.sub(r'\n\s*<script>\s*if \(\'serviceWorker\' in navigator\) \{.*?\}\s*</script>', '', content, flags=re.DOTALL)
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("PWA registration removed from all templates.")
