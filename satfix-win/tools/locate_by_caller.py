#!/usr/bin/env python3
"""通用「靠调用者定位」工具。

为什么需要它
------------
`ApplyModifierMult` 的定位成功靠的是**换了一条路**：函数体指纹分不出来
（75/65 个同形状候选），但它的**调用者**带独特的字符串字面量，于是：

    1. 在 Linux dump 里找「谁调用了目标函数」，并收集那些调用者里的字符串；
    2. 用字符串在 Windows dump 里认出同一个调用者；
    3. 看那个调用者 call 了哪个 FUN_ —— 那就是目标函数。

这个工具把上面三步自动化，供 satfix-win 剩下还没定位的目标复用。

用法::

    tools/locate_by_caller.py --linux <linux.cpp> --target "NShipUtil::CalcMaxShieldHitPoints"
    tools/locate_by_caller.py --linux <linux.cpp> --target "..." --win-caller <字符串>
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

DELIM = re.compile(r"^// =+ (.+?) End =+\s*$")
STR = re.compile(r'"([^"\\\n]{5,90})"')
# Linux 侧的调用形态：CClass::Method(  或  直接写出的符号名
def call_re(name: str) -> re.Pattern:
    # 目标名可能是 "NShipUtil::CalcMaxShieldHitPoints"，也可能是裸函数名
    esc = re.escape(name)
    return re.compile(r"(?<![\w:])" + esc + r"\s*\(")


def scan_linux(linux: Path, target: str) -> list[tuple[str, int, int, list[str]]]:
    """返回 [(caller_name, start_line, n_calls, strings)]"""
    rx = call_re(target)
    out = []
    name = None
    start = 1
    body: list[str] = []

    with linux.open(encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            m = DELIM.match(line)
            if m:
                if body:
                    hits = sum(1 for l in body if rx.search(l))
                    if hits:
                        strs: list[str] = []
                        for l in body:
                            strs.extend(STR.findall(l))
                        out.append((name or "<top>", start, hits, strs))
                name = m.group(1).strip()
                start = i
                body = []
                continue
            body.append(line)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--linux", type=Path, required=True)
    ap.add_argument("--target", required=True, help="Linux 侧的函数名（如 NShipUtil::CalcMaxArmorHitPoints）")
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    callers = scan_linux(args.linux, args.target)
    print(f'=== Linux 侧调用 "{args.target}" 的函数: {len(callers)} 个 ===')
    if not callers:
        print("（没有调用者 —— 可能是虚函数/只被间接调用，或名字写法不同）")
        return 1

    # 按「字符串数量」排序：字符串越多越容易在 Windows 侧认出这个调用者
    callers.sort(key=lambda c: (-len(set(c[3])), -c[2]))
    rich = [c for c in callers if c[3]]
    print(f"其中带字符串字面量的: {len(rich)}（这些才能跨平台认出）\n")

    for name, start, hits, strs in callers[: args.top]:
        uniq = [s for s, _ in Counter(strs).most_common()]
        flag = "★" if uniq else " "
        print(f"{flag} {name}  调用次数={hits}  行={start}")
        if uniq:
            print(f"     字符串: {uniq[:8]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
