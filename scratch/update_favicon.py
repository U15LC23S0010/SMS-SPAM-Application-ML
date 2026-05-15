import os

templates_dir = 'templates'
favicon_link = '<link rel="icon" type="image/png" href="/static/icon-192x192.png">'

target_templates = ['index.html', 'dashboard.html', 'login.html', 'register.html']

for filename in target_templates:
    filepath = os.path.join(templates_dir, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '<link rel="icon"' not in content:
            content = content.replace('</head>', f'    {favicon_link}\n</head>')
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print("Favicon updated across templates.")
