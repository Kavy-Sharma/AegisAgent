from pathlib import Path

web_dir = Path("web")
leaks = []
for p in web_dir.glob("*.py"):
    with open(p, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if ("jsonify" in line or "render_template" in line or "return f\"" in line or "msg = f\"" in line) and ("{e}" in line or "str(e)" in line):
                leaks.append(f"{p}:{i}: {line.strip()}")

print(f"Total leaked exceptions found in web responses: {len(leaks)}")
for leak in leaks:
    print("  ", leak)
assert len(leaks) == 0, f"Found {len(leaks)} leaked exceptions!"
print("GREP PROOF: Zero exceptions leaked in web responses!")

