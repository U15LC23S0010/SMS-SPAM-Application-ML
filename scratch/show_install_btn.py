import os
import re

templates_dir = 'templates'

# Old button with display: none
old_btn = 'id="pwa-install-btn" class="btn btn-primary" style="display: none;'
# New button with display: inline-flex (visible by default) and pulse class
new_btn = 'id="pwa-install-btn" class="btn btn-primary pulsing-install" style="display: inline-flex;'

target_templates = ['index.html', 'dashboard.html', 'analytics.html', 'classification.html', 'family.html', 'history.html', 'profile.html', 'settings.html']

for filename in target_templates:
    filepath = os.path.join(templates_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if old_btn in content:
            content = content.replace(old_btn, new_btn)
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("PWA Install buttons updated to be visible and pulsing.")
