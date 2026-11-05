"""Compare the fresh 4.5.3 decompilation with the 4.5.2 dump bodies."""
import difflib
import json
import re
from pathlib import Path

IDX = Path(r"C:\Users\A\Documents\ChatGPT\anti_stellaris\_analysis\win_dump_index.jsonl")
DUMP = Path(r"C:\Users\A\Documents\ChatGPT\anti_stellaris\_analysis\stellaris_4.5.2_win_source.cpp")
DEC = Path(r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\decomp_453.json")
SCAN = Path(r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\scan_453.json")
IMAGE_BASE = 0x140000000

dec = json.loads(DEC.read_text(encoding="utf-8"))
scan = json.loads(SCAN.read_text(encoding="utf-8"))["targets"]

want = {}
for key, rec in dec["targets"].items():
    old_rva = scan[key]["old_rva"]
    want["FUN_%x" % (IMAGE_BASE + old_rva)] = key
print("looking for %d old bodies" % len(want))

ranges = {}
with IDX.open(encoding="utf-8") as f:
    for line in f:
        o = json.loads(line)
        if o.get("fun") in want:
            ranges[o["fun"]] = (o["start"], o["end"])
print("index hits:", len(ranges))

bodies = {}
need = set(ranges.values())
maxend = max(e for _s, e in ranges.values())
minstart = min(s for s, _e in ranges.values())
with DUMP.open(encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f, 1):
        if i < minstart - 2:
            continue
        if i > maxend:
            break
        for fun, (s, e) in ranges.items():
            if s <= i <= e:
                bodies.setdefault(fun, []).append(line.rstrip("\n"))
                break

def norm(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    text = re.sub(r"0x[0-9a-fA-F]+", "0xN", text)
    text = re.sub(r"FUN_[0-9a-fA-F]+", "FUN_X", text)
    text = re.sub(r"[ \t]+", " ", text)
    toks = re.findall(r"[A-Za-z_][A-Za-z_0-9]*|0xN|\S", text)
    return toks

rows = []
for fun, key in want.items():
    old_body = "\n".join(bodies.get(fun, []))
    new_src = dec["targets"][key].get("decompiled", "")
    if not old_body or not new_src:
        rows.append((key, None, "missing old=%d new=%d" % (len(old_body), len(new_src))))
        continue
    a, b = norm(old_body), norm(new_src)
    r = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
    rows.append((key, r, "old_tok=%d new_tok=%d" % (len(a), len(b))))

rows.sort(key=lambda t: (t[1] is None, t[1] if t[1] is not None else 9))
print("%-22s %7s  %s" % ("key", "ratio", "tokens"))
for key, r, note in rows:
    print("%-22s %7s  %s" % (key, ("%.4f" % r) if r is not None else "n/a", note))
