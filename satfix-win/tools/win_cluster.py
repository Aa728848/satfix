#!/usr/bin/env python3
"""列出一段 RVA 区间内的全部函数块，用于「成簇定位」。

为什么有用
----------
Linux 侧 satfix 的目标 RVA 是已知的（satfix/satfix_targets.generated.hpp）。
把它们按地址排序会看到：同类成员（CFixedPoint 的 GetRounded / Sqrt / RoundTo…、
NShipUtil 的三个 CalcMax*）在 Linux 里**紧挨着排布**，而 MSVC 链接同类 COMDAT
单元的顺序往往与 GCC 一致。于是「已知成员的地址」就成了未知成员的锚点：
先算出 Linux 里的相对偏移，再在 Windows 的对应簇里按偏移找候选，最后读函数体确证。

用法::

    tools/win_cluster.py --lo 0x1b4c000 --hi 0x1b4d000
    tools/win_cluster.py --around 0x1b4c170 --span 0x400
    tools/win_cluster.py --lo 0x1b4c000 --hi 0x1b4d000 --linux
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_INDEX = HERE.parent.parent.parent / "_analysis" / "win_dump_index.jsonl"
LINUX_HEADER = HERE.parent.parent / "satfix" / "satfix_targets.generated.hpp"

# Linux 目标的 RVA 在生成的宏里，形如
#   X(key, "mangled", 0x04230850ull, "desc")
LINUX_X_RE = re.compile(r'X\((\w+),\s*"([^"]*)",\s*(0x[0-9a-fA-F]+)ull,\s*"([^"]*)"\)')


def load_index(index: Path) -> list[dict]:
    rows = []
    with index.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                d = json.loads(line)
                if d.get("rva") is not None:
                    rows.append(d)
    rows.sort(key=lambda d: d["rva"])
    return rows


def load_linux_targets() -> list[tuple[str, str, int, str]]:
    if not LINUX_HEADER.is_file():
        return []
    text = LINUX_HEADER.read_text(encoding="utf-8")
    return [(m.group(1), m.group(2), int(m.group(3), 16), m.group(4))
            for m in LINUX_X_RE.finditer(text)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    ap.add_argument("--lo", type=lambda s: int(s, 0))
    ap.add_argument("--hi", type=lambda s: int(s, 0))
    ap.add_argument("--around", type=lambda s: int(s, 0), help="以该 RVA 为中心")
    ap.add_argument("--span", type=lambda s: int(s, 0), default=0x400)
    ap.add_argument("--linux", action="store_true", help="附上 Linux 目标的相对偏移")
    ap.add_argument("--gap", action="store_true", help="在相邻函数之间打印空隙")
    args = ap.parse_args()

    if args.around is not None:
        lo, hi = args.around - args.span, args.around + args.span
    elif args.lo is not None:
        lo, hi = args.lo, args.hi if args.hi is not None else args.lo + 0x1000
    else:
        ap.error("需要 --lo/--hi 或 --around")

    rows = load_index(args.index)
    sel = [r for r in rows if lo <= r["rva"] < hi]
    print(f"# 区间 0x{lo:08x}..0x{hi:08x}  函数块 {len(sel)} 个")
    prev_end = None
    for r in sel:
        size = (r["end"] - r["start"])
        gap = ""
        if args.gap and prev_end is not None:
            # 函数块末尾行数差≈代码字节差不可靠，改用相邻 RVA 差
            pass
        print(f'{r["rva"]:08x}  {size:>5}L  {r["name"] or "":<38} [{r["fun"]}]')
        prev_end = r

    if args.gap:
        print("\n# 相邻 RVA 间距")
        for a, b in zip(sel, sel[1:]):
            print(f'  0x{a["rva"]:08x} -> 0x{b["rva"]:08x}  +0x{b["rva"] - a["rva"]:x}'
                  f'  ({a["name"] or a["fun"]} -> {b["name"] or b["fun"]})')

    if args.linux:
        lt = load_linux_targets()
        if not lt:
            print("没有 Linux 目标表", file=sys.stderr)
            return 1
        print("\n# Linux 目标 RVA（同表，供比对顺序/间距）")
        for key, mang, rva, desc in sorted(lt, key=lambda t: t[2]):
            print(f'  {rva:08x}  {key:<24} {desc[:60]}')

    return 0


if __name__ == "__main__":
    sys.exit(main())
