#!/usr/bin/env python3
"""给 Windows 反编译 dump 建函数索引，并按 RVA / FUN_ 名取出函数体。

为什么需要它
------------
`stellaris.exe` 没有 PDB、没有 C++ 符号，只有 110 个导出，所以 satfix 的 23 个目标
**不能**像 Linux 那样按 mangled 名 `dlsym` 解析。Windows 侧的办法是：
用定点算术的常量指纹在 110843 个函数块里筛出候选，再人工/结构化确证 RVA。

这个脚本是那套流程的地基：把 dump 切成函数块并建立索引，供
`win_fingerprint.py` 反复检索，避免每次都重扫 181 MB 文本。

dump 的排版约定（`verify_dump_format.py` 已校验的不变量）
--------------------------------------------------------
分隔符在**函数体之后**，不是之前：

    void FUN_140001d20(void)          <- 函数头 + 函数体
    {
      ...
    }
    // ============ FUN_140001d20 End ===============   <- 这一行属于上一个函数

被符号化的块名字写成 `Name [FUN_addr]`：

    // ============ ApplyModifierMult [FUN_1408b3700] End ===============

用法::

    tools/win_dump_index.py --dump <dump.cpp> --out <index.jsonl>
    tools/win_dump_index.py --dump <dump.cpp> --rva 0x1b4c0a0
    tools/win_dump_index.py --dump <dump.cpp> --fun FUN_141b4c0a0
    tools/win_dump_index.py --dump <dump.cpp> --rva 0x1b4c0a0 --body
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

IMAGE_BASE = 0x140000000

# 分隔符在函数体之后。块名的三种形态（先用宽松捕获，再分类，因为名字里自己可能带 `[`）：
#   FUN_140001d20                      纯地址名（109423 个）
#   ApplyModifierMult [FUN_1408b3700]  符号化名 + 地址
#   do_tolower / thunk_FUN_... / ReadMember [`scalar_deleting_destructor']  非 FUN_ 名（1420 个）
DELIM_RE = re.compile(r"^// =+ (?P<body>.*?) End =+\s*$")
FUN_NAME_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")
FUN_IN_BRACKETS_RE = re.compile(r"^(?P<name>.+) \[(?P<fun>FUN_[0-9a-fA-F]+)\]$")


def parse_delim(line: str) -> tuple[str | None, str | None] | None:
    """把分隔符行解析成 (fun, name)；不是分隔符行则返回 None。"""
    m = DELIM_RE.match(line)
    if not m:
        return None
    body = m.group("body").strip()
    mb = FUN_IN_BRACKETS_RE.match(body)
    if mb:
        return mb.group("fun"), mb.group("name")
    if FUN_NAME_RE.match(body):
        return body, None
    return None, body

# 函数定义头，例如 `void FUN_140001d20(void)`、`undefined8 FUN_x(...)`、`ulonglong FUN_x(longlong a)`
HEAD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ ]*?FUN_(?P<addr>[0-9a-fA-F]+)\s*\(")


def build_index(dump: Path, out: Path) -> int:
    """扫一遍 dump，输出 JSONL 索引；返回函数块数。"""
    cur_start: int | None = None
    cur_head: str | None = None
    count = 0

    with dump.open(encoding="utf-8", errors="replace") as f, out.open("w", encoding="utf-8") as w:
        for lineno, line in enumerate(f, 1):
            parsed = parse_delim(line)
            if parsed is not None:
                fun, name = parsed
                if fun is None and cur_head:
                    # 非 FUN_ 名：地址只能从头里挖
                    hm = HEAD_RE.match(cur_head)
                    if hm:
                        fun = "FUN_" + hm.group("addr")
                rva = (int(fun.split("_")[1], 16) - IMAGE_BASE) & 0xFFFFFFFFFFFFFFFF if fun else None
                rec = {
                    "fun": fun,
                    "rva": rva,
                    "name": name,
                    "start": cur_start if cur_start is not None else lineno,
                    "end": lineno,
                    "head": cur_head,
                }
                w.write(json.dumps(rec, ensure_ascii=False) + "\n")
                count += 1
                cur_start = lineno + 1
                cur_head = None
                continue

            if cur_head is None:
                hm = HEAD_RE.match(line)
                if hm:
                    cur_head = line.rstrip("\n")
                    if cur_start is None:
                        cur_start = lineno

    return count


def load_index(index: Path) -> list[dict]:
    rows = []
    with index.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def resolve(rows: list[dict], rva: int | None, fun: str | None) -> dict | None:
    if fun:
        for r in rows:
            if r["fun"] and r["fun"].lower() == fun.lower():
                return r
        return None
    if rva is not None:
        for r in rows:
            if r["rva"] == rva:
                return r
        # 没有精确命中就找包含它的函数（RVA 落在某函数体内部时很有用）
        cands = [r for r in rows if r["rva"] is not None and r["rva"] <= rva]
        return cands[-1] if cands else None
    return None


def print_body(dump: Path, rec: dict, ctx: int = 0) -> None:
    lo = max(1, rec["start"] - ctx)
    hi = rec["end"] + ctx
    with dump.open(encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            if lineno < lo:
                continue
            if lineno > hi:
                break
            print(f"{lineno:>9} {line.rstrip()}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", type=Path, required=True, help="反编译 dump（.cpp）")
    ap.add_argument("--out", type=Path, help="索引输出路径（JSONL）")
    ap.add_argument("--index", type=Path, help="已有的索引；给了就不重扫")
    ap.add_argument("--rva", type=lambda s: int(s, 0), help="按 RVA 查（可带 0x）")
    ap.add_argument("--fun", help="按 FUN_ 名查")
    ap.add_argument("--body", action="store_true", help="打印函数体")
    ap.add_argument("--ctx", type=int, default=0, help="函数体前后附带的行数")
    ap.add_argument("--list", action="store_true", help="列出索引里的全部函数（慎用，十万级）")
    args = ap.parse_args()

    if args.index:
        rows = load_index(args.index)
        print(f"读到索引 {args.index}: {len(rows)} 个函数块", file=sys.stderr)
    else:
        if not args.out:
            ap.error("没有 --index 时必须给 --out")
        n = build_index(args.dump, args.out)
        print(f"已建立索引 {args.out}: {n} 个函数块", file=sys.stderr)
        rows = load_index(args.out)

    if args.list:
        for r in rows:
            if r["name"]:
                print(f'{r["fun"]}\t0x{r["rva"]:08x}\t{r["name"]}')
        return 0

    if args.rva is None and args.fun is None:
        return 0

    rec = resolve(rows, args.rva, args.fun)
    if rec is None:
        print("没找到", file=sys.stderr)
        return 1
    print(f'{rec["fun"]}  0x{rec["rva"]:08x}  lines {rec["start"]}-{rec["end"]}  name={rec["name"]}')
    if args.body:
        print_body(args.dump, rec, args.ctx)
    return 0


if __name__ == "__main__":
    sys.exit(main())
