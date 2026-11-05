#!/usr/bin/env python
"""Structure-level matching for targets whose bytes changed.

Why: 4.5.2 -> 4.5.3 shifted some struct field offsets, so [rdi+0x13b] became
[rdi+0x13f].  A byte-level pattern cannot survive that, even though the
function is the same one.  So compare *instruction shapes*: mnemonic + operand
kinds + register names, with every immediate and displacement collapsed to a
placeholder.  Then rank candidates by token-sequence similarity.

Usage:
    python instr_match.py <key> [<key> ...] [--window 0x80000]
"""
from __future__ import annotations

import argparse
import difflib
import json
import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, x86_const

EXE = r"D:\Steam\steamapps\common\Stellaris\stellaris.exe"
OLD = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\old_bytes_452.json"
SCAN = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\scan_453.json"
IMAGE_BASE = 0x140000000
REG_NAME = {getattr(x86_const, n): n[8:].lower() for n in dir(x86_const) if n.startswith("X86_REG_")}


def pdata_functions(pe) -> dict:
    funcs = {}
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    if not dd.VirtualAddress:
        return funcs
    for s in pe.sections:
        if s.VirtualAddress <= dd.VirtualAddress < s.VirtualAddress + s.Misc_VirtualSize:
            blob = s.get_data()
            off = dd.VirtualAddress - s.VirtualAddress
            for i in range(dd.Size // 12):
                b, e, _u = struct.unpack_from("<III", blob, off + i * 12)
                if b and e > b:
                    funcs[b] = e - b
            break
    return funcs


def tokenize(code, va, max_insns=600):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    toks = []
    for insn in md.disasm(code, va):
        if len(toks) >= max_insns:
            break
        parts = [insn.mnemonic]
        for op in insn.operands:
            if op.type == x86_const.X86_OP_REG:
                parts.append("r:" + REG_NAME.get(op.reg, "?"))
            elif op.type == x86_const.X86_OP_IMM:
                parts.append("i")
            elif op.type == x86_const.X86_OP_MEM:
                m = op.mem
                parts.append("m:%s+%s*%d" % (REG_NAME.get(m.base, "-"), REG_NAME.get(m.index, "-"), m.scale))
            else:
                parts.append("?")
        toks.append(" ".join(parts))
    return toks


def sim(a, b):
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keys", nargs="+")
    ap.add_argument("--window", default="0x80000")
    ap.add_argument("--top", type=int, default=6)
    args = ap.parse_args()
    win = int(args.window, 0)

    old = json.loads(Path(OLD).read_text(encoding="utf-8"))
    scan = json.loads(Path(SCAN).read_text(encoding="utf-8"))
    pe = pefile.PE(EXE, fast_load=True)
    funcs = pdata_functions(pe)
    starts = sorted(funcs)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text").get_data()
    text_rva = 0x1000

    def code_at(rva, size):
        o = rva - text_rva
        return text[o:o + size]

    for key in args.keys:
        rec = old["targets"][key]
        old_toks = tokenize(bytes.fromhex(rec["bytes"]), rec["entry_va"])
        old_rva = rec["rva"]
        cands = [s for s in starts if old_rva - win <= s <= old_rva + win]
        scored = []
        for s in cands:
            size = funcs[s]
            new_toks = tokenize(code_at(s, min(size, 4096)), IMAGE_BASE + s)
            scored.append((sim(old_toks, new_toks), s, size))
        scored.sort(reverse=True)
        print("=== %s: old 0x%08X, %d insns, %d candidates" % (key, old_rva, len(old_toks), len(cands)))
        for sco, s, size in scored[:args.top]:
            print("    sim=%.4f  rva=0x%08X  delta=%+#x  size=%d" % (sco, s, s - old_rva, size))
        fz = (scan["targets"][key].get("fuzzy") or [[0, 0]])
        fz_rva = fz[0][1]
        rank = next((i for i, item in enumerate(scored) if item[1] == fz_rva), None)
        if rank is not None:
            print("    fuzzy candidate 0x%08X rank=%d score=%.4f" % (fz_rva, rank, scored[rank][0]))
        else:
            print("    fuzzy candidate 0x%08X not in candidate set" % fz_rva)
    return 0


if __name__ == "__main__":
    sys.exit(main())
