import re, pathlib

FILES = [
    "tests/unit/test_fintech_primitives.py",
    "tests/unit/test_healthcare_primitives.py",
    "tests/unit/test_infra_primitives_phase8.py",
    "tests/property/test_fintech_primitive_properties.py",
]

def fix_file(path_str):
    path = pathlib.Path(path_str)
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    changed = False
    while i < len(lines):
        line = lines[i]
        # Detect start of a solve() call (but not already-fixed ones)
        if re.search(r'\bsolve\(', line):
            # Collect lines until parens balance (depth == 0)
            segment = [line]
            depth = line.count('(') - line.count(')')
            j = i + 1
            while depth > 0 and j < len(lines):
                segment.append(lines[j])
                depth += lines[j].count('(') - lines[j].count(')')
                j += 1
            call_text = ''.join(segment)
            if 'timeout_ms' not in call_text:
                if len(segment) == 1:
                    # Single-line: insert ', timeout_ms=5_000' before the final ')'
                    new_line = re.sub(r'\)(\s*)$', r', timeout_ms=5_000)\1', line)
                    segment = [new_line]
                else:
                    # Multi-line: insert a timeout_ms line before the closing ')' line
                    closing_line = segment[-1]
                    indent = len(closing_line) - len(closing_line.lstrip())
                    timeout_line = ' ' * (indent + 4) + 'timeout_ms=5_000,\n'
                    segment.insert(-1, timeout_line)
                changed = True
            result.extend(segment)
            i = j
        else:
            result.append(line)
            i += 1

    if changed:
        path.write_text(''.join(result), encoding='utf-8')
        print(f"Fixed: {path_str}")
    else:
        print(f"Already clean: {path_str}")

for f in FILES:
    try:
        fix_file(f)
    except FileNotFoundError:
        print(f"Not found: {f}")
