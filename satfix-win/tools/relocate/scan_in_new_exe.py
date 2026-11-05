#!/usr/bin/env python
"""Locate the 4.5.2 target functions inside the 4.5.3 exe by masked byte matching.

Idea: the target function bodies are almost certainly unchanged between 4.5.2
and 4.5.3 (patch release).  What changes is:
  * the absolute address (RVA),
  * the rel32 displacement of every call/jmp,
  * the disp32 of every RIP-relative data reference.

So we take the 4.5.2 function bytes out of the old Ghidra project, mask exactly
those operand bytes (capstone decides which), and scan the new exe's .text for
the same masked pattern.  A unique hit == same machine code == same function.

Usage:
    python scan_in_new_exe.py [--old old_bytes_452.json] [--exe <path>] [--out <json>]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pefile
from capstone import (CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_64, Cs,
                      x86_const)

DEFAULT_OLD = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\old_bytes_452.json"
DEFAULT_EXE = r"D:\Steam\steamapps\common\Stellaris\stellaris.exe"
DEFAULT_OUT = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\scan_453.json"
IMAGE_BASE = 0x140000000


def build_mask(code: bytes, va: int) -> bytearray:
    """1 = keep byte, 0 = wildcard."""
    mask = bytearray(b"\x01" * len(code))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    covered = 0
    for insn in md.disasm(code, va):
        if insn.address != va + covered:
            # capstone lost sync: keep bytes as-is from here on
            break
        is_branch = insn.group(CS_GRP_CALL) or insn.group(CS_GRP_JUMP)
        if is_branch and insn.imm_size:
            off = insn.address - va + insn.imm_offset
            for i in range(insn.imm_size):
                if off + i < len(mask):
                    mask[off + i] = 0
        for op in insn.operands:
            if op.type == x86_const.X86_OP_MEM and op.mem.base == x86_const.X86_REG_RIP:
                off = insn.address - va + insn.disp_offset
                for i in range(insn.disp_size):
                    if off + i < len(mask):
                        mask[off + i] = 0
        covered += insn.size
    return mask


def longest_run(mask: bytearray) -> tuple[int, int]:
    best_start, best_len = 0, 0
    i = 0
    while i < len(mask):
        if mask[i]:
            j = i
            while j < len(mask) and mask[j]:
                j += 1
            if j - i > best_len:
                best_start, best_len = i, j - i
            i = j
        else:
            i += 1
    return best_start, best_len


def scan(code: bytes, mask: bytearray, blob: bytes, blob_base_rva: int) -> list[tuple[int, int]]:
    """Return [(new_rva, matched_bytes)] best-effort candidates."""
    a_off, a_len = longest_run(mask)
    if a_len < 6:
        return []
    anchor = code[a_off:a_off + a_len]
    limit = len(blob) - len(code)
    hits: list[tuple[int, int]] = []
    pos = blob.find(anchor)
    while pos != -1 and pos <= limit + len(code):
        start = pos - a_off
        if 0 <= start <= limit:
            ok = True
            for k in range(len(code)):
                if mask[k] and blob[start + k] != code[k]:
                    ok = False
                    break
            if ok:
                hits.append((blob_base_rva + start, len(code)))
        pos = blob.find(anchor, pos + 1)
    return hits


def partial_score(code: bytes, mask: bytearray, blob: bytes, start: int) -> float:
    n = min(len(code), len(blob) - start)
    kept = sum(1 for i in range(n) if mask[i])
    if not kept:
        return 0.0
    same = sum(1 for i in range(n) if mask[i] and blob[start + i] == code[i])
    return same / max(kept, len(code) and kept)


def scan_fuzzy(code: bytes, mask: bytearray, blob: bytes, blob_base_rva: int, top: int = 5):
    """Anchor on the longest 12-byte clean run, score candidates partially."""
    a_off, a_len = longest_run(mask)
    if a_len < 6:
        return []
    take = min(a_len, 12)
    anchor = code[a_off:a_off + take]
    scores = []
    pos = blob.find(anchor)
    while pos != -1:
        start = pos - a_off
        if 0 <= start <= len(blob) - 16:
            scores.append((partial_score(code, mask, blob, start), blob_base_rva + start))
        pos = blob.find(anchor, pos + 1)
    scores.sort(reverse=True)
    return scores[:top]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", default=DEFAULT_OLD)
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    old = json.loads(Path(args.old).read_text(encoding="utf-8"))
    pe = pefile.PE(args.exe, fast_load=True)
    text = None
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1")
        if name == ".text":
            text = s
            break
    if text is None:
        print("no .text section", file=sys.stderr)
        return 2
    blob = text.get_data()
    base_rva = text.VirtualAddress
    print(f"[scan] .text rva=0x{base_rva:X} size={len(blob)}")

    report = {"exe": args.exe, "text_rva": base_rva, "targets": {}}
    for key, rec in old["targets"].items():
        if not rec.get("bytes"):
            print(f"[scan] {key}: no old bytes, skip")
            continue
        code = bytes.fromhex(rec["bytes"])
        mask = build_mask(code, rec["entry_va"])
        hits = scan(code, mask, blob, base_rva)
        entry = {"old_rva": rec["rva"], "old_size": len(code), "hits": []}
        for rva, size in hits:
            entry["hits"].append({"rva": rva, "delta": rva - rec["rva"]})
        if not hits:
            entry["fuzzy"] = scan_fuzzy(code, mask, blob, base_rva)
        report["targets"][key] = entry
        kept = sum(mask)
        print(f"[scan] {key:22s} old=0x{rec['rva']:08X} size={len(code):5d} keep={kept:5d} hits={len(hits)}"
              + ("" if hits else f"  (fuzzy top: {[(round(s,3), hex(r)) for s, r in entry.get('fuzzy', [])[:3]]})"))
        for h in entry["hits"]:
            print(f"           -> new rva 0x{h['rva']:08X}  delta {h['delta']:+#x}")

    Path(args.out).write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"[scan] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
