import os
import glob
import re

files = glob.glob('**/*.html', recursive=True) + glob.glob('**/*.js', recursive=True)

replacements = [
    (r'color:\s*#f1f5f9', 'color:var(--text-primary)'),
    (r"color:\s*'#f1f5f9'", "color:'var(--text-primary)'"),
    (r'color:\s*#94a3b8', 'color:var(--text-secondary)'),
    (r"color:\s*'#94a3b8'", "color:'var(--text-secondary)'"),
    (r'color:\s*#475569', 'color:var(--text-tertiary)'),
    (r"color:\s*'#475569'", "color:'var(--text-tertiary)'")
]

for file in files:
    with open(file, 'r') as f:
        content = f.read()
    
    new_content = content
    for pattern, repl in replacements:
        new_content = re.sub(pattern, repl, new_content)
        
    if new_content != content:
        with open(file, 'w') as f:
            f.write(new_content)
        print(f'Updated {file}')
