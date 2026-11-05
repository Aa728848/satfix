#!/usr/bin/env python
"""Independent check: is each candidate RVA a real function start in the new exe?

Uses the PE exception directory (.pdata): every non-leaf function has one
RUNTIME_FUNCTION {DWORD BeginAddress; DWORD EndAddress; DWORD UnwindInfo}.
BeginAddress is the function's entry RVA, straight from the compiler -- no
heuristics.  Also reports the new function size so we can see whether the body
grew or shrank.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pefile

EXE = r"D:\Steam\steamapps\common\Stellaris\stellaris.exe"
SCAN = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\scan_453.json"


def pdata_functions(pe) -> dict[int, int]:
    """rva -> size, from the exception directory."""
    funcs: dict[int, int] = {}
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    if not dd.VirtualAddress:
        return funcs
    sec = None
    for s in pe.sections:
        if s.VirtualAddress <= dd.VirtualAddress < s.VirtualAddress + s.Misc_VirtualSize:
            sec = s
            break
    if sec is None:
        return funcs
    blob = sec.get_data()
    off = dd.VirtualAddress - sec.VirtualAddress
    n = dd.Size // 12
    for i in range(n):
        b, e, u = struct.unpack_from("<III", blob, off + i * 12)
        if b and e > b:
            funcs[b] = e - b
    return funcs


def main() -> int:
    scan = json.loads(Path(SCAN).read_text(encoding="utf-8"))
    pe = pefile.PE(EXE, fast_load=True)
    funcs = pdata_functions(pe)
    print(f"[pdata] {len(funcs)} runtime functions, imagebase 0x{pe.OPTIONAL_HEADER.ImageBase:X}")

    starts = sorted(funcs)
    import bisect

    ok = bad = 0
    for key, rec in scan["targets"].items():
        hits = rec.get("hits") or []
        if not hits:
            print(f"[pdata] {key:22s} SKIP (no exact hit; fuzzy {rec.get('fuzzy', [])[:1]})")
            continue
        rva = hits[0]["rva"]
        if rva in funcs:
            i = bisect.bisect_left(starts, rva)
            nxt = starts[i + 1] if i + 1 < len(starts) else None
            gap = (nxt - rva) if nxt else None
            print(f"[pdata] {key:22s} 0x{rva:08X} OK  pdata_size={funcs[rva]:5d}  next_start_gap={gap}")
            ok += 1
        else:
            i = bisect.bisect_left(starts, rva)
            prev = starts[i - 1] if i else None
            inside = prev is not None and prev <= rva < prev + funcs[prev]
            print(f"[pdata] {key:22s} 0x{rva:08X} NOT-A-START  inside_func=0x{prev:08X} offsets={rva-prev if inside else None}")
            bad += 1
    print(f"[pdata] verified starts: {ok}, not-starts: {bad}")

    # 两个未命中的目标：在旧 RVA 附近找出所有函数起点，便于后续做结构匹配
    for key in ("diplo_weight", "ship_size_max_hp"):
        old = scan["targets"][key]["old_rva"]
        win = 0x40000
        cands = [s for s in starts if old - win <= s <= old + win]
        print(f"[pdata] {key}: {len(cands)} function starts within +-0x{win:X} of old 0x{old:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
