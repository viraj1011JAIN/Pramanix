"""Remove fixed-flaw entries from FLAW_AUDIT.md."""
import re
import sys

FIXED_IDS = {10, 11, 33, 35, 36, 48, 55, 75, 85, 87, 153, 154, 155, 161,
             263, 265, 269, 270, 272, 311, 312, 313, 314, 316, 317, 334, 335}

# Match ### (any severity emoji) #N — or ### ✅ FIXED — #N
SECTION_HDR = re.compile(r"^###\s+.*?#(\d+)[\s—\-]")
# Match table data rows: | N | ...
TABLE_ROW = re.compile(r"^\|\s*(\d+)\s*\|")

path = r"c:\Pramanix\docs\FLAW_AUDIT.md"

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

out = []
skip = False
removed_sections = []
removed_rows = []

i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.rstrip("\n").rstrip()

    # Check for section header
    m = SECTION_HDR.match(stripped)
    if m:
        flaw_num = int(m.group(1))
        if flaw_num in FIXED_IDS:
            skip = True
            removed_sections.append(flaw_num)
            i += 1
            continue
        else:
            skip = False  # entering a new unfixed section, stop skipping

    if skip:
        # Skip content until we hit a fresh `---` separator OR
        # the next non-fixed section header
        if stripped == "---":
            skip = False
            # Keep the separator for formatting
            out.append(line)
        i += 1
        continue

    # Filter summary-table rows for fixed flaws
    tm = TABLE_ROW.match(stripped)
    if tm:
        row_num = int(tm.group(1))
        if row_num in FIXED_IDS:
            removed_rows.append(row_num)
            i += 1
            continue

    out.append(line)
    i += 1

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)

print(f"Input lines:  {len(lines)}")
print(f"Output lines: {len(out)}")
print(f"Removed section headers for: {sorted(set(removed_sections))}")
print(f"Removed table rows for:      {sorted(set(removed_rows))}")
