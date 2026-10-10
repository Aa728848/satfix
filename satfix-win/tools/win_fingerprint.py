#!/usr/bin/env python3
"""用**函数体形状**在 Windows dump 里定位 satfix 目标。

为什么不靠 `win_linux_mapping_final_452.json` 的名字
----------------------------------------------------
那份映射是用**字符串字面量指纹**匹配出来的（rule1/rule2/rule3），
它的 `confidence: exact` 意思是「这个字符串指纹唯一命中」，
**不等于「这个函数就是同名 Linux 函数」**。实测反例：

* `FUN_1408b3700` 被标为 `ApplyModifierMult`，实际是一个 modifier
  token 分发器（比较 `param_3` 与 0x2a7b/0xb5/0x31a …）；
* `FUN_1408b3e00` 被标为 `ApplyModifierMult`，实际是**析构函数**
  （写回 vtable、释放内存）。

所以本工具只看**函数体结构**：定点算术的常量、运算符与调用形状。
`stellaris.exe` 没有 PDB，但 CFixedPoint 的成员函数体非常小且具特征
（例如 `operator fpml::fixed_point<...,15>()` 只有一行公式），
足以做到逐字确证。

用法::

    tools/win_fingerprint.py --index _analysis/win_dump_index.jsonl \\
        --dump _analysis/stellaris_4.5.2_win_symbolized.cpp --report
    tools/win_fingerprint.py ... --dup-of 0x1b4c170     # 找函数体完全相同的孪生
    tools/win_fingerprint.py ... --out targets.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量指纹：CFixedPoint 是十进制定点，1.0 = 100000
# ---------------------------------------------------------------------------
F_DIV = re.compile(r"/\s*100000\b")
F_MOD = re.compile(r"%\s*100000\b")
F_MUL = re.compile(r"\*\s*100000\b")
F_PLUS50 = re.compile(r"\+\s*50000\b")
F_PLUSNEG50 = re.compile(r"\+\s*-50000\b")
F_MINUS50 = re.compile(r"-\s*50000\b")
F_HX4000 = re.compile(r"0x40000000\b")
F_HXC350 = re.compile(r"0xc3500000\b", re.I)
F_HX8000 = re.compile(r"0x8000\b")
# fpml 二进制方言（1.0 = 2^15 / 2^7）用算术右移
F_SHR15 = re.compile(r">>\s*0xf\b")
F_SHR7 = re.compile(r">>\s*7\b")

CONV_TAIL = re.compile(
    r"\(\s*\**\s*\w+\s*%\s*100000\s*\)\s*\*\s*0x40000000\s*\)\s*/\s*0xc3500000\s*\+\s*"
    r"\(\s*\**\s*\w+\s*/\s*100000\s*\)\s*\*\s*0x8000",
    re.I,
)


def norm_body(text: str) -> str:
    """把函数体规范化成可比较的形状串：去空白、去注释、变量名归一。"""
    t = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    t = re.sub(r"//[^\n]*", " ", t)
    t = re.sub(r"\b(local_\w+|uStack_\w+|bStack\w*_\w+|param_\d+|lVar\d+|uVar\d+|iVar\d+|"
               r"plVar\d+|puVar\d+|piVar\d+|bVar\d+|cVar\d+|uStack\w*|DAT_\w+|LAB_\w+|"
               r"FUN_[0-9a-fA-F]+|PTR_\w+)\b", "V", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def shape_key(body: str) -> str:
    """只保留常量与运算符的骨架，用于跨函数找同形体。"""
    t = norm_body(body)
    t = re.sub(r"\b\w+\b", lambda m: m.group(0) if re.match(r"^\d+$", m.group(0)) else "V", t)
    return t


def strip_head(text: str) -> str:
    """去掉函数签名行，只留函数体。"""
    i = text.find("{")
    return text[i:] if i >= 0 else text


def read_body(dump: Path, rec: dict) -> str:
    lines = []
    with dump.open(encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if n < rec["start"]:
                continue
            if n > rec["end"] - 1:
                break
            lines.append(line)
    return "".join(lines)


def features(body: str) -> set[str]:
    s: set[str] = set()
    if F_DIV.search(body):
        s.add("div1e5")
    if F_MOD.search(body):
        s.add("mod1e5")
    if F_MUL.search(body):
        s.add("mul1e5")
    if F_PLUS50.search(body):
        s.add("plus50000")
    if F_PLUSNEG50.search(body):
        s.add("plus_neg50000")
    if F_MINUS50.search(body):
        s.add("minus50000")
    if F_HX4000.search(body):
        s.add("0x40000000")
    if F_HXC350.search(body):
        s.add("0xc3500000")
    if F_HX8000.search(body):
        s.add("0x8000")
    if F_SHR15.search(body):
        s.add("shr15")
    if F_SHR7.search(body):
        s.add("shr7")
    return s


def classify(body: str, feats: set[str], rec: dict) -> list[str]:
    """给一个函数体打候选标签（可多个；需要人工确证）。"""
    tags = []
    b = norm_body(body)

    # CFixedPoint::operator fpml::fixed_point<...,15>() const
    #   *ret = ((x % 100000) * 0x40000000) / 0xc3500000 + (x / 100000) * 0x8000;
    if CONV_TAIL.search(b):
        tags.append("cfx_to_fp15")

    # CFixedPoint::GetRounded() / GetRounded64()
    #   v = x + (-50000); if (x >= 0) v = x + 50000; return v / 100000;
    if {"plus50000", "plus_neg50000", "div1e5"} <= feats:
        tags.append("cfx_get_rounded")

    # RoundTo / 四舍五入到 100000 的倍数
    if {"plus50000", "div1e5", "mul1e5"} <= feats or {"minus50000", "div1e5", "mul1e5"} <= feats:
        tags.append("cfx_round_maybe")

    # 游戏语义的拆分乘法 (a*b)/1e5 with (X%1e5)*Y 分支
    if {"mod1e5", "div1e5", "mul1e5"} <= feats:
        tags.append("cfx_split_mul")

    # fpml 换算（二进制方言）
    if "shr15" in feats:
        tags.append("fpml15_shift")
    if "shr7" in feats:
        tags.append("fpml7_shift")

    return tags


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", type=Path, required=True)
    ap.add_argument("--index", type=Path, required=True)
    ap.add_argument("--report", action="store_true", help="打印分类汇总")
    ap.add_argument("--tag", help="只列出带某个标签的函数")
    ap.add_argument("--dup-of", type=lambda s: int(s, 0), help="找与给定 RVA 函数体形状完全相同的函数")
    ap.add_argument("--out", type=Path, help="把结果写成 JSON")
    ap.add_argument("--limit", type=int, default=60)
    args = ap.parse_args()

    rows = [json.loads(l) for l in args.index.open(encoding="utf-8") if l.strip()]

    # 只对"碰过定点常量"的函数取体，避免读 181MB
    cand = []
    for r in rows:
        if r["rva"] is None:
            continue
        cand.append(r)

    # 先用一次顺序扫描把所有块的指纹算出来（只读一遍文件）
    by_tag: dict[str, list] = {}
    shapes: dict[str, list] = {}
    tagged_rows = []

    with args.dump.open(encoding="utf-8", errors="replace") as f:
        idx = 0
        buf: list[str] = []
        lineno = 0
        while idx < len(cand):
            rec = cand[idx]
            # 读该块
            while lineno < rec["start"] - 1:
                line = f.readline()
                if not line:
                    break
                lineno += 1
            buf = []
            while lineno < rec["end"]:
                line = f.readline()
                if not line:
                    break
                lineno += 1
                buf.append(line)
            body = "".join(buf)
            feats = features(body)
            if not feats:
                idx += 1
                continue
            tags = classify(body, feats, rec)
            sk = shape_key(strip_head(body))
            shapes.setdefault(sk, []).append((rec["rva"], rec["fun"], rec["name"], tags))
            entry = {
                "fun": rec["fun"],
                "rva": rec["rva"],
                "name": rec["name"],
                "features": sorted(feats),
                "tags": tags,
                "lines": rec["end"] - rec["start"],
            }
            tagged_rows.append(entry)
            for t in tags:
                by_tag.setdefault(t, []).append(entry)
            idx += 1

    print(f"扫过 {len(cand)} 个块，命中定点常量指纹的 {len(tagged_rows)} 个", file=sys.stderr)

    if args.dup_of is not None:
        target_shape = None
        for sk, members in shapes.items():
            if any(m[0] == args.dup_of for m in members):
                target_shape = sk
                break
        if target_shape is None:
            print(f"0x{args.dup_of:x} 没有可比较的形状", file=sys.stderr)
            return 1
        members = shapes[target_shape]
        print(f"与 0x{args.dup_of:x} 函数体形状完全相同的函数：{len(members)} 个")
        for rva, fun, name, tags in sorted(members):
            star = "  <== 起点" if rva == args.dup_of else ""
            print(f"  0x{rva:08x}  {fun}  name={name}  tags={tags}{star}")
        return 0

    if args.report:
        print("\n=== 分类计数 ===")
        for t, items in sorted(by_tag.items(), key=lambda kv: -len(kv[1])):
            print(f"  {t:20s} {len(items)}")

    if args.tag:
        items = by_tag.get(args.tag, [])
        print(f"\n=== {args.tag}: {len(items)} 个（按体量升序，越小越像薄封装）===")
        for e in sorted(items, key=lambda e: e["lines"])[: args.limit]:
            print(f'  0x{e["rva"]:08x}  lines={e["lines"]:5d}  {e["fun"]}  name={e["name"]}  {e["features"]}')

    if args.out:
        args.out.write_text(
            json.dumps({"candidates": tagged_rows, "by_tag": {k: len(v) for k, v in by_tag.items()}},
                       ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        print(f"\n已写 {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
