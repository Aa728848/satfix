#!/usr/bin/env python
"""4.6 重定位工具箱：PE 函数边界 / 常量指纹检索 / 反汇编 / 调用点 / Linux 4.6 dump 索引。

为什么需要它：4.5.3 -> 4.6 是内容大版本，字节掩码只能捞回「体形没变」的那批（本轮 25 个里捞回 11 个）。
剩下的目标必须按 AGENTS.md 的标准流程走：从 **4.6 Linux 反编译（有符号名）** 读出函数的独占常量 /
ModifierType 序列 -> 回 Windows exe 里按立即数检索 -> 用 .pdata 证明它是函数起点 -> 看调用点定 ABI。

子命令（都在仓库根目录跑）::

    python satfix-win/tools/relocate/locate46.py pdata                     # .pdata 统计 + 段信息
    python satfix-win/tools/relocate/locate46.py pdata --rva 0x1CFF460    # 该 RVA 属于哪个函数
    python satfix-win/tools/relocate/locate46.py dis --rva 0x1CFF460 --len 96
    python satfix-win/tools/relocate/locate46.py scan-imm --imm 0x13b7c,0x13b88,0x13c38
    python satfix-win/tools/relocate/locate46.py callers --rva 0x1CFF460
    python satfix-win/tools/relocate/locate46.py bytes --rva 0x1CFF460 --len 64
    python satfix-win/tools/relocate/locate46.py index                     # 建 Linux 4.6 dump 索引
    python satfix-win/tools/relocate/locate46.py linux --name CalcMaxHitPoints --body
    python satfix-win/tools/relocate/locate46.py linux --name CFixedPoint::Sqrt --body --max 1

`--exe` / `--dump` 可覆盖默认路径。
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import sys
from pathlib import Path

import pefile
from capstone import (CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_64, Cs,
                      x86_const)

WS = Path(r"C:\Users\A\Documents\ChatGPT\anti_stellaris")
DEFAULT_EXE = Path(r"D:\Steam\steamapps\common\Stellaris\stellaris.exe")
DEFAULT_DUMP = WS / "stellaris_4.6_source.cpp"
DEFAULT_INDEX = WS / "_analysis" / "linux46_index.json"
IMAGE_BASE = 0x140000000


# --------------------------------------------------------------------------- PE
class Exe:
    """只读加载一次 .text / .pdata，后面所有查询都走内存。"""

    def __init__(self, path: Path):
        self.path = path
        self.pe = pefile.PE(str(path), fast_load=True)
        self.timestamp = self.pe.FILE_HEADER.TimeDateStamp
        secs = {s.Name.rstrip(b"\x00").decode("latin-1"): s for s in self.pe.sections}
        text = secs[".text"]
        self.text_rva = text.VirtualAddress
        self.text = text.get_data()
        pdata = secs[".pdata"]
        raw = pdata.get_data()
        self.funcs: list[tuple[int, int]] = []
        for off in range(0, len(raw) - 11, 12):
            begin, end, _unwind = (int.from_bytes(raw[off + 4 * i:off + 4 * i + 4], "little") for i in range(3))
            if begin == 0 or end <= begin:
                continue
            self.funcs.append((begin, end))
        self.funcs.sort()
        self.starts = [b for b, _ in self.funcs]

    def containing(self, rva: int):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i < 0:
            return None
        begin, end = self.funcs[i]
        return (begin, end) if begin <= rva < end else None

    def is_start(self, rva: int) -> bool:
        i = bisect.bisect_left(self.starts, rva)
        return i < len(self.starts) and self.starts[i] == rva

    def read(self, rva: int, size: int) -> bytes:
        off = rva - self.text_rva
        return self.text[off:off + size]


def fmt(rva: int) -> str:
    return f"0x{rva:08X}"


def dis_range(exe: Exe, rva: int, size: int, va_base: int = IMAGE_BASE):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = exe.read(rva, size)
    out = []
    for insn in md.disasm(code, va_base + rva):
        out.append(f"  {insn.address - va_base + 0:016X}  {insn.bytes.hex():<20} {insn.mnemonic:<8} {insn.op_str}")
    return "\n".join(out)


# -------------------------------------------------------------------- commands
def cmd_pdata(exe: Exe, args) -> int:
    print(f"exe        : {exe.path}")
    print(f"build stamp: 0x{exe.timestamp:08X}")
    print(f".text      : rva {fmt(exe.text_rva)}  size {len(exe.text)}")
    print(f".pdata     : {len(exe.funcs)} functions")
    if args.rva is not None:
        rva = int(args.rva, 0)
        span = exe.containing(rva)
        if span is None:
            print(f"{fmt(rva)}: 不在任何 .pdata 函数内（叶子函数或被裁掉）")
            return 0
        begin, end = span
        print(f"{fmt(rva)}: 函数 {fmt(begin)} .. {fmt(end)}  size={end - begin}  start={exe.is_start(rva)}")
    return 0


def cmd_dis(exe: Exe, args) -> int:
    rva = int(args.rva, 0)
    print(f"; dis {fmt(rva)} len={args.len}")
    print(dis_range(exe, rva, args.len))
    return 0


def cmd_bytes(exe: Exe, args) -> int:
    rva = int(args.rva, 0)
    data = exe.read(rva, args.len)
    print(data.hex())
    return 0


def cmd_scan_imm(exe: Exe, args) -> int:
    imms = [int(x, 0) for x in args.imm.split(",") if x.strip()]
    hits: dict[int, set[int]] = {}
    total = 0
    for v in imms:
        if not (0 <= v <= 0xFFFFFFFF):
            print(f"  skip {hex(v)}: 超出 imm32 范围")
            continue
        pat = v.to_bytes(4, "little")
        per = 0
        pos = exe.text.find(pat)
        while pos != -1:
            rva = exe.text_rva + pos
            span = exe.containing(rva)
            if span is not None:
                hits.setdefault(span[0], set()).add(v)
            per += 1
            total += 1
            pos = exe.text.find(pat, pos + 1)
        if args.verbose:
            print(f"  imm {hex(v):>10}: {per} 处字节命中")
    ranked = sorted(hits.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    print(f"候选函数（命中 >= {args.min} 个常量）：")
    shown = 0
    for begin, got in ranked:
        if len(got) < args.min:
            continue
        end = exe.containing(begin)[1]
        miss = [hex(v) for v in imms if v not in got]
        print(f"  {fmt(begin)}  size={end - begin:6d}  hit {len(got)}/{len(imms)}  缺: {miss}")
        shown += 1
        if shown >= args.top:
            break
    if shown == 0:
        print("  （无）")
    return 0


def direct_call_sites(exe: Exe, rva: int) -> list[int]:
    """扫 .text 里所有 E8 rel32 / E9 rel32 指向 rva 的位置（调用点或跳转）。"""
    text = exe.text
    base = exe.text_rva
    out = []
    pat = b"\xe8"
    pos = text.find(pat)
    while pos != -1:
        if pos + 5 <= len(text):
            rel = int.from_bytes(text[pos + 1:pos + 5], "little", signed=True)
            site_rva = base + pos
            if site_rva + 5 + rel == rva:
                out.append(site_rva)
        pos = text.find(pat, pos + 1)
    return out


def cmd_callers(exe: Exe, args) -> int:
    rvas = [int(x, 0) for x in args.rva.split(",") if x.strip()]
    owners: dict[int, set[int]] = {}
    for rva in rvas:
        sites = direct_call_sites(exe, rva)
        print(f"call 到 {fmt(rva)} 的调用点: {len(sites)}")
        for site in sites[:args.top]:
            span = exe.containing(site)
            owner = fmt(span[0]) if span else "（叶子/无 .pdata）"
            print(f"  调用点 {fmt(site)}  所属函数 {owner}")
        owners[rva] = {exe.containing(s)[0] for s in sites if exe.containing(s)}
    if len(rvas) > 1:
        common = set.intersection(*owners.values())
        print(f"\n同时调用这 {len(rvas)} 个目标的函数（交集）: {len(common)}")
        for begin in sorted(common):
            end = exe.containing(begin)[1]
            print(f"  {fmt(begin)}  size={end - begin}")
    if args.dis and rvas:
        sites = direct_call_sites(exe, rvas[0])
        if sites:
            span = exe.containing(sites[0])
            if span:
                start = span[0]
                size = min(sites[0] + 16 - start, args.dis)
                print(f"\n; 第一个调用点的上下文（从 {fmt(start)} 起 {size} 字节）")
                print(dis_range(exe, start, size))
    return 0


def cmd_callees(exe: Exe, args) -> int:
    """线性反汇编一个函数，列出它直接 call 的目标（身份/ABI 核对常用）。"""
    rva = int(args.rva, 0)
    span = exe.containing(rva)
    if span is None:
        print(f"{fmt(rva)} 不在 .pdata 里；用 --len 手工给长度", file=sys.stderr)
        if not args.len:
            return 2
        begin, end = rva, rva + args.len
    else:
        begin, end = span
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    code = exe.read(begin, end - begin)
    n = 0
    for insn in md.disasm(code, IMAGE_BASE + begin):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            target = int(insn.op_str, 16) - IMAGE_BASE
            print(f"  {fmt(insn.address - IMAGE_BASE)}  call {fmt(target)}")
            n += 1
    print(f"共 {n} 个直接 call")
    return 0


def _linux_load() -> tuple[dict, bytes]:
    idx_path = DEFAULT_INDEX
    payload = json.loads(Path(idx_path).read_text(encoding="utf-8"))
    data = Path(payload["dump"]).read_bytes()
    return payload["index"], data


def cmd_digest(args) -> int:
    """打印一个 Linux 4.6 函数的「指纹摘要」：完整签名、被调函数、数字字面量、行数。

    名字按每个函数体前的 /* ... */ 注释匹配（那份注释带完整限定名），避免同名函数串台。
    """
    index, data = _linux_load()
    needle = args.name
    want = []
    for name, spans in index.items():
        for start, end in spans:
            head = data[start:start + 600].decode("utf-8", "replace")
            m = re.search(r"/\* (.+?) \*/", head)
            sig = m.group(1) if m else ""
            if needle in sig or needle == name:
                want.append((name, sig, start, end))
    if not want:
        print(f"没找到签名包含 {needle!r} 的函数", file=sys.stderr)
        return 1
    print(f"匹配 {len(want)} 个函数体")
    for name, sig, start, end in want[:args.top]:
        body = data[start:end].decode("utf-8", "replace")
        lines = body.splitlines()
        print("\n" + "=" * 78)
        print(f"/* {sig} */   [{name}]  offsets {start}..{end}  lines={len(lines)}  chars={len(body)}")
        calls = []
        for line in lines:
            for mm in re.finditer(r"(\b[A-Za-z_][\w]*::[A-Za-z_~][\w]*|\bFUN_[0-9a-f]+)\s*\(", line):
                if mm.group(1) not in calls:
                    calls.append(mm.group(1))
        print(f"被调函数 ({len(calls)}): " + ", ".join(calls))
        lits = {}
        for line in lines:
            for mm in re.finditer(r"0x([0-9a-fA-F]{2,8})\b", line):
                v = int(mm.group(1), 16)
                if 0x10 <= v <= 0xFFFFFFFF:
                    lits[v] = lits.get(v, 0) + 1
        print(f"数字字面量 ({len(lits)}): " + " ".join(f"{v:#x}" for v in sorted(lits)))
        if args.save:
            out = Path(args.save).with_name(Path(args.save).stem + f"_{name}_{start}.txt")
            out.write_text(body, encoding="utf-8")
            print(f"已保存函数体 -> {out}")
    return 0


# ---------------------------------------------- 立即数「落在某个寄存器里」的检索
# MSVC 传参常见形态（64 位）：
#   mov r9d, imm32   -> 41 b9 <imm32>
#   mov r9,  imm32   -> 49 c7 c1 <imm32>
#   mov r8d, imm32   -> 41 b8 <imm32>
#   mov r8,  imm32   -> 49 c7 c0 <imm32>
#   mov edx, imm32   -> ba <imm32>
#   mov rdx, imm32   -> 48 c7 c2 <imm32>
#   mov ecx, imm32   -> b9 <imm32>
#   mov rcx, imm32   -> 48 c7 c1 <imm32>
REG_ENCODINGS: dict[str, list[bytes]] = {
    "r9d": [b"\x41\xb9"],
    "r9": [b"\x49\xc7\xc1", b"\x41\xb9"],
    "r8d": [b"\x41\xb8"],
    "r8": [b"\x49\xc7\xc0", b"\x41\xb8"],
    "edx": [b"\xba"],
    "rdx": [b"\x48\xc7\xc2", b"\xba"],
    "ecx": [b"\xb9"],
    "rcx": [b"\x48\xc7\xc1", b"\xb9"],
    "eax": [b"\xb8"],
}


def cmd_scan_imm_fn(exe: Exe, args) -> int:
    """按「某个立即数被装进某个寄存器」检索函数（比裸 imm32 扫描精确得多）。

    例：ModifierType 作为第 4 个参数走 r9d，于是
        scan-imm-fn --regs r9d --imm 0x20,0x21
    能直接把「同时出现这两个 ModifierType」的函数挑出来。
    """
    imms = [int(x, 0) for x in args.imm.split(",") if x.strip()]
    regs = [r.strip() for r in args.regs.split(",") if r.strip()]
    hits: dict[int, set[int]] = {}
    for reg in regs:
        if reg not in REG_ENCODINGS:
            print(f"  未知寄存器 {reg}（可用: {', '.join(REG_ENCODINGS)}）")
            continue
        for prefix in REG_ENCODINGS[reg]:
            for v in imms:
                pat = prefix + v.to_bytes(4, "little")
                pos = exe.text.find(pat)
                while pos != -1:
                    rva = exe.text_rva + pos
                    span = exe.containing(rva)
                    if span is not None:
                        hits.setdefault(span[0], set()).add(v)
                    pos = exe.text.find(pat, pos + 1)
    ranked = sorted(hits.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    print(f"候选函数（命中 >= {args.min} 个立即数）：")
    shown = 0
    for begin, got in ranked:
        if len(got) < args.min:
            continue
        end = exe.containing(begin)[1]
        miss = [hex(v) for v in imms if v not in got]
        print(f"  {fmt(begin)}  size={end - begin:6d}  hit {len(got)}/{len(imms)}  缺: {miss}")
        shown += 1
        if shown >= args.top:
            break
    if shown == 0:
        print("  （无）")
    return 0


# ------------------------------------------------------- 与旧函数体的形状比对
def build_mask(code: bytes, va: int) -> bytearray:
    """1 = 必须相同，0 = 通配（call/jmp 的 rel32、rip-relative 的 disp32）。"""
    mask = bytearray(b"\x01" * len(code))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    covered = 0
    for insn in md.disasm(code, va):
        if insn.address != va + covered:
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


def cmd_compare(exe: Exe, args) -> int:
    """把候选函数的新字节，与 old_bytes_453.json 里同名目标的旧函数体按掩码比对。"""
    old_path = Path(args.old)
    old = json.loads(old_path.read_text(encoding="utf-8"))
    key = args.key
    if key not in old["targets"]:
        print(f"{old_path} 里没有 {key}", file=sys.stderr)
        return 2
    rec = old["targets"][key]
    code = bytes.fromhex(rec["bytes"])
    mask = build_mask(code, rec["entry_va"])
    kept = sum(mask)
    rva = int(args.rva, 0)
    new = exe.read(rva, len(code))
    same = sum(1 for i in range(len(code)) if mask[i] and new[i] == code[i])
    span = exe.containing(rva)
    old_rva = rec["rva"]
    print(f"{key}: 旧 0x{old_rva:08X} size={len(code)}  ->  候选 0x{rva:08X}")
    print(f"  掩码字节一致率 = {same}/{kept} = {same / max(kept, 1):.4f}")
    if span:
        print(f"  .pdata: {fmt(span[0])} .. {fmt(span[1])}  size={span[1] - span[0]}  start={exe.is_start(rva)}")
    else:
        print("  .pdata: 无条目（叶子函数或未登记）")
    if args.dis:
        print("\n; 新候选反汇编")
        print(dis_range(exe, rva, min(args.dis, len(code) + 32)))
    return 0


def cmd_verify(exe: Exe, args) -> int:
    """对一张 key -> 新 RVA 的映射表，批量给出「旧长度 / 新 .pdata / 掩码一致率」验收表。"""
    old = json.loads(Path(args.old).read_text(encoding="utf-8"))
    table = json.loads(Path(args.map).read_text(encoding="utf-8"))
    rows = []
    for key, new_rva in table.items():
        rec = old["targets"].get(key)
        if rec is None:
            rows.append((key, "?", "旧表里没有", ""))
            continue
        code = bytes.fromhex(rec["bytes"])
        mask = build_mask(code, rec["entry_va"])
        kept = sum(mask)
        rva = int(new_rva, 0) if isinstance(new_rva, str) else int(new_rva)
        new = exe.read(rva, len(code))
        same = sum(1 for i in range(len(code)) if mask[i] and new[i] == code[i])
        ratio = same / max(kept, 1)
        span = exe.containing(rva)
        pdata = f"{fmt(span[0])} size={span[1] - span[0]} start={exe.is_start(rva)}" if span else "无条目(叶子)"
        rows.append((key, f"0x{rec['rva']:08X}", f"0x{rva:08X}", f"{len(code)}", pdata, f"{ratio:.3f}"))
    print(f"{'key':22s} {'4.5.3':>10s} {'4.6':>10s} {'old':>5s}  {'新 .pdata':38s} 掩码一致率")
    for key, o, n, size, pdata, ratio in rows:
        print(f"{key:22s} {o:>10s} {n:>10s} {size:>5s}  {pdata:38s} {ratio}")
    return 0


# --------------------------------------------- 字符串 / 全局地址的引用（xref）
REX_W = (0x48, 0x49, 0x4C, 0x4D)


def rip_ref_sites(exe: Exe, targets: set[int]) -> dict[int, list[int]]:
    """快速扫 .text，找 `lea/mov reg,[rip+disp32]` 形态里指向 targets 的位置。

    只做两个最常见的编码形态（带 REX.W 与不带），命中后用 capstone 复核那一条指令。
    """
    text = exe.text
    base = exe.text_rva
    out: dict[int, list[int]] = {t: [] for t in targets}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    n = len(text)
    for pos in range(n - 8):
        b0 = text[pos]
        has_rex = b0 in REX_W
        op = text[pos + 1] if has_rex else b0
        if op not in (0x8D, 0x8B, 0x89):
            continue
        modrm_at = pos + 2 if has_rex else pos + 1
        if text[modrm_at] & 0xC7 != 0x05:
            continue
        disp_at = modrm_at + 1
        disp = int.from_bytes(text[disp_at:disp_at + 4], "little", signed=True)
        insn_len = (disp_at + 4) - pos
        target = base + pos + insn_len + disp
        if target not in out:
            continue
        # capstone 复核：确认这一条确实是 rip-relative 引用而不是巧合字节
        insn = next(md.disasm(text[pos:pos + insn_len], IMAGE_BASE + base + pos, count=1), None)
        if insn is None or insn.size != insn_len:
            continue
        out[target].append(base + pos)
    return out


def file_off_to_rva(exe: Exe, off: int) -> int | None:
    for s in exe.pe.sections:
        size = max(s.SizeOfRawData, s.Misc_VirtualSize)
        if s.PointerToRawData <= off < s.PointerToRawData + size:
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None


def cmd_find_str(exe: Exe, args) -> int:
    """在 exe 里按字符串找 VA，再找引用它的代码位置。"""
    needle = args.str.encode("utf-8")
    raw = exe.path.read_bytes()
    vas = []
    pos = raw.find(needle)
    while pos != -1 and len(vas) < args.max:
        rva = file_off_to_rva(exe, pos)
        if rva is not None:
            vas.append(rva)
        pos = raw.find(needle, pos + 1)
    print(f"字符串 {args.str!r} 命中 {len(vas)} 处")
    for rva in vas:
        print(f"  字符串 VA {fmt(rva)}")
    if not vas:
        return 1
    refs = rip_ref_sites(exe, set(vas))
    for rva in vas:
        sites = refs.get(rva, [])
        print(f"\n引用 {fmt(rva)} 的位置: {len(sites)}")
        for site in sites[:args.top]:
            span = exe.containing(site)
            owner = f"{fmt(span[0])} (size={span[1] - span[0]})" if span else "（无 .pdata）"
            print(f"  {fmt(site)}  所属函数 {owner}")
    return 0


def cmd_find_xref(exe: Exe, args) -> int:
    """给一个 VA（全局变量 / 字符串），列出引用它的代码位置与所属函数。"""
    targets = {int(x, 0) for x in args.va.split(",") if x.strip()}
    refs = rip_ref_sites(exe, targets)
    for t in sorted(targets):
        sites = refs.get(t, [])
        print(f"{fmt(t)}: {len(sites)} 处引用")
        for site in sites[:args.top]:
            span = exe.containing(site)
            owner = f"{fmt(span[0])} (size={span[1] - span[0]})" if span else "（无 .pdata）"
            print(f"  {fmt(site)}  所属函数 {owner}")
    return 0


# --------------------------------------------------------------- linux 4.6 dump
SEP = re.compile(rb"// =+ (.+?) End =+\r?\n")


def cmd_index(args) -> int:
    dump = Path(args.dump)
    out = Path(args.out)
    print(f"读取 {dump} ({dump.stat().st_size} 字节) …")
    data = dump.read_bytes()
    marks = [(m.start(), m.group(1).decode("utf-8", "replace")) for m in SEP.finditer(data)]
    print(f"命中分隔行 {len(marks)} 条")
    index = {}
    prev_end = 0
    for start, name in marks:
        index.setdefault(name, []).append([prev_end, start])
        prev_end = start
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"dump": str(dump), "size": len(data), "count": len(marks), "index": index}
    out.write_text(json.dumps(payload), encoding="utf-8")
    print(f"写入 {out}（{len(index)} 个不同名字）")
    return 0


def cmd_linux(args) -> int:
    idx_path = Path(args.out)
    if not idx_path.exists():
        print(f"缺少索引 {idx_path}，先跑 `locate46.py index`", file=sys.stderr)
        return 2
    payload = json.loads(idx_path.read_text(encoding="utf-8"))
    index = payload["index"]
    needle = args.name
    names = [n for n in index if needle in n]
    exact = [n for n in names if n == needle]
    names = exact + [n for n in names if n not in exact]
    if not names:
        print(f"没有名字包含 {needle!r} 的函数", file=sys.stderr)
        return 1
    print(f"匹配 {len(names)} 个：")
    for n in names[:args.top]:
        spans = index[n]
        print(f"  {n}  x{len(spans)}  offsets={[s for s, _ in spans][:4]}")
    if not args.body:
        return 0
    data = Path(payload["dump"]).read_bytes()
    for n in names[:args.max]:
        for start, end in index[n][:args.max_bodies]:
            print("\n" + "=" * 78)
            print(f"// {n}  [bytes {start}..{end}]")
            print("=" * 78)
            print(data[start:end].decode("utf-8", "replace"))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", default=str(DEFAULT_EXE))
    ap.add_argument("--dump", default=str(DEFAULT_DUMP))
    ap.add_argument("--out", default=str(DEFAULT_INDEX))
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pdata"); p.add_argument("--rva", default=None)
    p = sub.add_parser("dis"); p.add_argument("--rva", required=True); p.add_argument("--len", type=int, default=64)
    p = sub.add_parser("bytes"); p.add_argument("--rva", required=True); p.add_argument("--len", type=int, default=64)
    p = sub.add_parser("scan-imm")
    p.add_argument("--imm", required=True)
    p.add_argument("--min", type=int, default=2)
    p.add_argument("--top", type=int, default=12)
    p.add_argument("--verbose", action="store_true")
    p = sub.add_parser("callers")
    p.add_argument("--rva", required=True, help="单个 RVA，或逗号分隔多个（给多个时求交集）")
    p.add_argument("--top", type=int, default=8)
    p.add_argument("--dis", type=int, default=0)
    p = sub.add_parser("scan-imm-fn")
    p.add_argument("--regs", default="r9d", help="逗号分隔，如 r9d,r8d,edx")
    p.add_argument("--imm", required=True)
    p.add_argument("--min", type=int, default=2)
    p.add_argument("--top", type=int, default=12)
    p = sub.add_parser("compare")
    p.add_argument("--key", required=True)
    p.add_argument("--rva", required=True)
    p.add_argument("--old", default=str(Path(__file__).with_name("old_bytes_453.json")))
    p.add_argument("--dis", type=int, default=0)
    p = sub.add_parser("verify")
    p.add_argument("--map", required=True)
    p.add_argument("--old", default=str(Path(__file__).with_name("old_bytes_453.json")))
    p = sub.add_parser("find-str")
    p.add_argument("--str", required=True)
    p.add_argument("--top", type=int, default=8)
    p.add_argument("--max", type=int, default=4)
    p = sub.add_parser("find-xref")
    p.add_argument("--va", required=True, help="逗号分隔的 VA")
    p.add_argument("--top", type=int, default=12)
    p = sub.add_parser("callees")
    p.add_argument("--rva", required=True)
    p.add_argument("--len", type=int, default=0)
    sub.add_parser("index")
    p = sub.add_parser("digest")
    p.add_argument("--name", required=True)
    p.add_argument("--top", type=int, default=3)
    p.add_argument("--save", default=None)
    p = sub.add_parser("linux")
    p.add_argument("--name", required=True)
    p.add_argument("--body", action="store_true")
    p.add_argument("--top", type=int, default=20)
    p.add_argument("--max", type=int, default=1)
    p.add_argument("--max-bodies", dest="max_bodies", type=int, default=1)

    args = ap.parse_args()
    if args.cmd == "index":
        return cmd_index(args)
    if args.cmd == "linux":
        return cmd_linux(args)
    if args.cmd == "digest":
        return cmd_digest(args)
    exe = Exe(Path(args.exe))
    handler = {
        "pdata": cmd_pdata,
        "dis": cmd_dis,
        "bytes": cmd_bytes,
        "scan-imm": cmd_scan_imm,
        "callers": cmd_callers,
        "callees": cmd_callees,
        "scan-imm-fn": cmd_scan_imm_fn,
        "compare": cmd_compare,
        "verify": cmd_verify,
        "find-str": cmd_find_str,
        "find-xref": cmd_find_xref,
    }[args.cmd]
    return handler(exe, args)


if __name__ == "__main__":
    sys.exit(main())
