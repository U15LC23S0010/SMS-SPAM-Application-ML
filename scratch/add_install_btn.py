import os
import re

templates_dir = 'templates'

install_btn_html = """
                <button id="pwa-install-btn" class="btn btn-primary" style="display: none; align-items: center; gap: 8px; font-size: 0.8rem; padding: 6px 12px; margin-right: 12px; border-radius: 12px; background: var(--primary); color: white; border: none; cursor: pointer; font-weight: 700;">
                    <i data-lucide="download" style="width: 14px;"></i> Install Hub
                </button>"""

pwa_script_tag = '<script src="{{ url_for(\'static\', filename=\'pwa.js\') }}"></script>'

# List of templates to modify
target_templates = ['index.html', 'dashboard.html', 'analytics.html', 'classification.html', 'family.html', 'history.html', 'profile.html', 'settings.html']

for filename in target_templates:
    filepath = os.path.join(templates_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 1. Clear previous unreg/kill scripts
        content = re.sub(r'\n\s*<script>\s*if \(\'serviceWorker\' in navigator\) \{.*?\}\s*</script>', '', content, flags=re.DOTALL)
        
        # 2. Add Install Button
        # For dashboard-like templates (with nav-right)
        if '<div class="nav-right">' in content:
            content = content.replace('<div class="nav-right">', '<div class="nav-right">' + install_btn_html)
        # For landing page (index.html)
        elif 'Sign In</a>' in content:
            content = content.replace('Sign In</a>', 'Sign In</a>' + install_btn_html)

        # 3. Add PWA script tag
        if pwa_script_tag not in content:
            content = content.replace('</body>', pwa_script_tag + '</body>')

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("PWA Install buttons and logic added to templates.")
