#!/usr/bin/env python3
"""按 PLUGIN_HANDBOOK.zh-CN 的规则检查 satfix 插件包。

对应手册第 13 节的「发布前检查清单」里**能自动查**的部分，
以及第 4.4 节的启动器校验规则（清单合法性与路径约束）。

查什么
------
清单（手册 4.2 / 4.3 / 4.4）:
  * schema == 2
  * id 非空且只含 [A-Za-z0-9._-]
  * dll 非空、相对路径、不含 ..
  * dll 指向的文件存在
  * config[].file 不含 / \\ ..
  * config[].default 是包内相对路径且文件存在
  * game.exe_timestamps 形状合法

包（手册 3 / 10.1）:
  * **不**包含 config\\、logs\\
  * 不包含写进游戏目录的东西（不能自查，但至少确认没有 seed_files）

用法::

    tools/check_plugin_pkg.py plugin
    tools/check_plugin_pkg.py plugin --exe D:\\...\\stellaris.exe   # 顺便核对时间戳
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
TS_RE = re.compile(r"^(0[xX])?[0-9A-Fa-f]{1,8}$")

ok_count = 0
bad: list[str] = []


def ok(cond: bool, what: str) -> bool:
    global ok_count
    if cond:
        ok_count += 1
        print(f"  [PASS] {what}")
    else:
        bad.append(what)
        print(f"  [FAIL] {what}")
    return cond


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pkg", type=Path, help="插件文件夹（含 stl-plugin.json）")
    ap.add_argument("--exe", type=Path, help="顺便核对 exe_timestamps 与真实 exe")
    args = ap.parse_args()

    pkg: Path = args.pkg
    print(f"=== 检查插件包: {pkg} ===")
    if not pkg.is_dir():
        sys.exit(f"不是目录: {pkg}")

    mf = pkg / "stl-plugin.json"
    print("\n[1] 清单存在且是合法 JSON")
    if not ok(mf.is_file(), "stl-plugin.json 存在"):
        return 1
    raw = mf.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        ok(False, f"清单是 UTF-8: {e}")
        return 1
    ok(True, "清单是 UTF-8（容忍 BOM）")
    try:
        m = json.loads(text)
    except json.JSONDecodeError as e:
        ok(False, f"清单是合法 JSON: {e}")
        return 1
    ok(True, "清单是合法 JSON")
    ok(isinstance(m, dict), "清单是对象")

    print("\n[2] 必填字段（手册 4.2）")
    ok(m.get("schema") == 2, f'schema == 2（实际 {m.get("schema")!r}）')
    pid = m.get("id", "")
    ok(bool(pid) and bool(ID_RE.match(pid)), f"id 合法: {pid!r}")
    ok(bool(m.get("name")), f'name 非空: {m.get("name")!r}')
    dll = m.get("dll", "")
    ok(bool(dll), f"dll 非空: {dll!r}")
    ok(not dll.startswith(("/", "\\")) and not re.match(r"^[A-Za-z]:", dll),
       "dll 是相对路径")
    ok(".." not in dll, "dll 不含 ..")

    print("\n[3] dll 文件存在（手册 4.4）")
    ok((pkg / dll).is_file(), f"存在: {pkg / dll}")

    print("\n[4] config 条目（手册 4.3 / 4.4）")
    for c in m.get("config", []) or []:
        f = c.get("file", "")
        ok(bool(f) and "/" not in f and "\\" not in f and ".." not in f,
           f"config.file 合法（无子目录）: {f!r}")
        d = c.get("default")
        if d is not None:
            ok(not d.startswith(("/", "\\")) and ".." not in d,
               f"config.default 是包内相对路径: {d!r}")
            ok((pkg / d).is_file(), f"默认文件存在: {pkg / d}")

    print("\n[5] exe_timestamps 形状（手册 4.2 / 7）")
    ts = (m.get("game") or {}).get("exe_timestamps")
    if ts is None:
        ok(False, "game.exe_timestamps 存在（应当列上已测试的构建）")
    else:
        ok(isinstance(ts, list), "exe_timestamps 是数组")
        for t in ts:
            ok(isinstance(t, str) and bool(TS_RE.match(t)), f"时间戳形状合法: {t!r}")
        if not ts:
            print("      [note] 空数组 = 启动器不检查；此时 DLL 必须自己做版本检查")

    print("\n[6] 包内容（手册 3 / 10.1）")
    ok(not (pkg / "config").exists(), "包里没有 config\\（属于用户）")
    ok(not (pkg / "logs").exists(), "包里没有 logs\\（属于用户）")
    ok("seed_files" not in m, "没有用 schema 1 的 seed_files（手册附录 C）")
    ok(not (pkg / "update").is_dir() or True, "（update 字段可选，不检查）")
    # 不该有编译中间产物
    for junk in ("build", "__pycache__"):
        ok(not (pkg / junk).exists(), f"包里没有 {junk}\\")
    for p in pkg.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".obj", ".pdb", ".lib", ".exp", ".ilk"):
            ok(False, f"包里不该有编译中间产物: {p.relative_to(pkg)}")
            break
    else:
        ok(True, "包里没有 .obj/.pdb/.lib/.exp/.ilk")

    print("\n[7] 与真实 exe 核对（可选）")
    if args.exe:
        try:
            import pefile
            pe = pefile.PE(str(args.exe), fast_load=True)
            real = pe.FILE_HEADER.TimeDateStamp
            listed = [int(t, 16) for t in (ts or [])]
            ok(real in listed,
               f"exe 时间戳 0x{real:08X} 在 exe_timestamps 里（{ts}）")
        except ImportError:
            print("      [skip] 没装 pefile")
    else:
        print("      [skip] 没给 --exe")

    print(f"\n=== 结果：通过 {ok_count} 项，失败 {len(bad)} 项 ===")
    for b in bad:
        print(f"  !! {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
