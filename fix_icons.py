import re
with open('web/index.html', 'r', encoding='utf-8') as f:
    txt = f.read()
txt = re.sub(r'<i data-lucide="([^"]+)"([^>]*)></i>', r'<Icon name="\1"\2 />', txt)
with open('web/index.html', 'w', encoding='utf-8') as f:
    f.write(txt)
print('Done!')
