import os

reference = """# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""

def update_files(directory):
    for root, dirs, files in os.walk(directory):
        if '.venv' in dirs: dirs.remove('.venv')
        if '__pycache__' in dirs: dirs.remove('__pycache__')
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if "docs/THESIS.tex" not in content:
                    lines = content.split('\n')
                    insert_idx = 0
                    for i, line in enumerate(lines):
                        if line.startswith('# SPDX-') or line.startswith('# Copyright'):
                            insert_idx = i + 1
                        elif not line.startswith('#'):
                            break
                    
                    lines.insert(insert_idx, reference.strip())
                    
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(lines))

update_files(r'C:\Pramanix\benchmarks')
print("Done benchmarks")
