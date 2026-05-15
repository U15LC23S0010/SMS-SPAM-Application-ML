import os

templates_dir = 'templates'

target_templates = ['index.html', 'dashboard.html', 'analytics.html', 'classification.html', 'family.html', 'history.html', 'profile.html', 'settings.html']

for filename in target_templates:
    filepath = os.path.join(templates_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Rename "Install Hub" to "Install App"
        content = content.replace('Install Hub', 'Install App')
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("PWA Install buttons renamed to 'Install App'.")
