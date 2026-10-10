#!/usr/bin/env python3
"""从指定的 Stellaris 二进制生成 satfix_targets.generated.hpp。

用法::

    tools/gen_targets.py <binary>                 # 写 generated 头文件
    tools/gen_targets.py <binary> -o other.hpp    # 指定输出
    tools/gen_targets.py <binary> --check         # 只比对，不写；有漂移则 exit 1
    tools/gen_targets.py <binary> --list          # 只打印解析结果

为什么要这么干
--------------
游戏是**非 PIE** 的 ET_EXEC（基址 0x400000），所以 ``nm`` 给出的地址就是运行时地址，
可以直接硬编码 —— 但**每次游戏更新这些地址都会变**。

所以运行时解析以 **mangled 名**为准（``shk::resolve`` 先 ``dlsym``，再读
``/proc/self/exe`` 的 ``.symtab``/``.dynsym``）；本脚本生成的地址只作兜底，
同时把"这批地址取自哪个 build"记进头文件，方便以后 ``--check`` 发现漂移。

Stellaris 的符号在 ``.dynsym`` 里有 18 万+ 条，所以正常情况下 dlsym 就能命中，
硬编码地址几乎用不上；真正需要它的场景是：符号被 LTO/内联掉之后。
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from find_stellaris import find_all as _find_stellaris_dirs
except Exception:  # pragma: no cover
    _find_stellaris_dirs = None

# ---------------------------------------------------------------------------
# 目标清单：key, mangled name, 人类可读描述
#
# mangled 名跨版本稳定（除非 Paraodox 改了函数签名）；地址不稳定。
# 新增目标只要往这里加一行。
# ---------------------------------------------------------------------------
TARGETS: list[tuple[str, str, str]] = [
    # --- 修正系统的乘法出口（satfix 的主战场） ---
    (
        "apply_mul_cfx",
        "_ZN9CModifier17ApplyModifierMultER11CFixedPointRKS_12ModifierTypeb",
        "CModifier::ApplyModifierMult(CFixedPoint&, CModifier const&, ModifierType, bool)",
    ),
    (
        "apply_mul_fp15",
        "_ZN9CModifier17ApplyModifierMultERN4fpml11fixed_pointIxLh48ELh15EEERKS_12ModifierTypeb",
        "CModifier::ApplyModifierMult(fpml::fixed_point<...,15>&, ...)",
    ),
    # --- CFixedPoint 的全部 9 个非内联成员 ---
    (
        "cfx_sqrt",
        "_ZNK11CFixedPoint4SqrtEv",
        "CFixedPoint::Sqrt() const",
    ),
    (
        "cfx_safe_sqrt",
        "_ZNK11CFixedPoint8SafeSqrtEv",
        "CFixedPoint::SafeSqrt() const",
    ),
    (
        "cfx_safe_sqrt_int",
        "_ZN11CFixedPoint8SafeSqrtEx",
        "CFixedPoint::SafeSqrt(long long)",
    ),
    (
        "cfx_get_rounded",
        "_ZNK11CFixedPoint10GetRoundedEv",
        "CFixedPoint::GetRounded() const",
    ),
    (
        "cfx_get_rounded64",
        "_ZNK11CFixedPoint12GetRounded64Ev",
        "CFixedPoint::GetRounded64() const",
    ),
    (
        "cfx_round_to",
        "_ZN11CFixedPoint7RoundToERKS_",
        "CFixedPoint::RoundTo(CFixedPoint const&)",
    ),
    (
        "cfx_atan2",
        "_ZN11CFixedPoint5Atan2ERKS_S1_",
        "CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&)",
    ),
    (
        "cfx_get_rounded_fp15",
        "_ZN11CFixedPoint10GetRoundedERKN4fpml11fixed_pointIxLh48ELh15EEE",
        "CFixedPoint::GetRounded(fpml::fixed_point<...,15> const&)",
    ),
    (
        "cfx_to_fp15",
        "_ZNK11CFixedPointcvN4fpml11fixed_pointIxLh48ELh15EEEEv",
        "CFixedPoint::operator fpml::fixed_point<...,15>() const",
    ),
    # --- 变量系统（mod 最容易叠到溢出的地方） ---
    (
        "var_multiply",
        "_ZNK23CMultiplyVariableEffect13ExecuteActualER11CEventScope",
        "CMultiplyVariableEffect::ExecuteActual(CEventScope&) const",
    ),
    (
        "var_add",
        "_ZNK18CAddVariableEffect13ExecuteActualER11CEventScope",
        "CAddVariableEffect::ExecuteActual(CEventScope&) const",
    ),
    # --- 战斗力/军力指数（pow 链，后期舰队就可能越界） ---
    (
        "mpe15",
        "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh48ELh15EEES2_",
        "NCombatRules::CalcMilitaryPowerExponent(fpml<...,15>, fpml<...,15>)",
    ),
    (
        "mpe7",
        "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh56ELh7EEES2_",
        "NCombatRules::CalcMilitaryPowerExponent(fpml<...,7>, fpml<...,7>)",
    ),
    # --- 外交权重（舰队部分在后期极易溢出，用户实测确认） ---
    (
        "diplo_weight",
        "_ZNK7CPopJob20CalcDiplomaticWeightERK9CPopGroup",
        "CPopJob::CalcDiplomaticWeight(CPopGroup const&) const",
    ),
    # --- 护盾上限（用户实测"护盾溢出"不在已 hook 的关口上，补一个观测点） ---
    (
        "shield_max",
        "_ZN9NShipUtil22CalcMaxShieldHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip",
        "NShipUtil::CalcMaxShieldHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)",
    ),
    (
        "armor_max",
        "_ZN9NShipUtil21CalcMaxArmorHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip",
        "NShipUtil::CalcMaxArmorHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)",
    ),
    (
        "hull_max",
        "_ZN9NShipUtil16CalcMaxHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip",
        "NShipUtil::CalcMaxHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)",
    ),
]

# ---------------------------------------------------------------------------
# 只"解析来调用"、不 hook 的辅助函数（影子复算用）。
# 也放进生成表，这样拼错符号名会被 --list / --check 立刻抓到
# （2026-10-09 就踩过一次：CVariables::GetVariable 是 const 成员，
#   漏了 _ZNK 里的 K，结果变量影子整条退化成透传）。
# ---------------------------------------------------------------------------
HELPERS: list[tuple[str, str, str]] = [
    (
        "access_var_pointer",
        "_Z21AccessVariablePointerR11CEventScopeRK7CString",
        "AccessVariablePointer(CEventScope&, CString const&)",
    ),
    (
        "cvars_get",
        "_ZNK10CVariables11GetVariableERK7CString",
        "CVariables::GetVariable(CString const&) const",
    ),
    (
        "cvars_set",
        "_ZN10CVariables11SetVariableERK7CString11CFixedPoint",
        "CVariables::SetVariable(CString const&, CFixedPoint)",
    ),
    (
        "cfp_getvalue",
        "_ZNK24CFixedPointVariableValue8GetValueER11CEventScope",
        "CFixedPointVariableValue::GetValue(CEventScope&) const",
    ),
]

HEADER_TEMPLATE = """\
// ===========================================================================
//  自动生成，不要手改 —— 由 tools/gen_targets.py 产出
//
//  来源二进制 : {binary}
//  游戏版本串 : {version}
//  生成时间   : {when}
//  符号来源   : {source}
//  命中       : {found}/{total}
//
//  重新生成（不传参数就用 satfix.conf / 自动探测到的群星二进制）：
//      tools/gen_targets.py
//      tools/gen_targets.py /path/to/stellaris
//  发现漂移（游戏更新后）：
//      tools/gen_targets.py --check
// ===========================================================================
#ifndef SATFIX_TARGETS_GENERATED_HPP
#define SATFIX_TARGETS_GENERATED_HPP

#include <cstdint>

#define SATFIX_TARGETS_VERSION "{version}"
#define SATFIX_TARGETS_BINARY  "{binary}"
#define SATFIX_TARGETS_FOUND   "{found}/{total}"

// 每一项: X(key, mangled_symbol, fallback_address, description)
// addr == 0 表示这次没在二进制里找到该符号（hook 会被跳过并告警）。
#define SATFIX_TARGETS(X) \\
{body}

// 辅助函数（只解析调用，不 hook）
#define SATFIX_HELPERS(X) \\
{helpers}

#endif  // SATFIX_TARGETS_GENERATED_HPP
"""


def run_nm(binary: Path, dynamic: bool) -> list[tuple[int, str]]:
    cmd = ["nm"] + (["-D"] if dynamic else []) + [str(binary)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        sys.exit("找不到 nm，请先装 binutils")
    except subprocess.CalledProcessError as exc:
        # nm -D 在某些二进制上会返回非 0，但不影响 stdout
        out = exc.stdout or ""

    result: list[tuple[int, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, _typ, name = parts[0], parts[1], parts[2]
        if name.startswith("__") or not name.startswith("_Z"):
            continue
        try:
            result.append((int(addr, 16), name))
        except ValueError:
            continue
    return result


def game_version(binary: Path) -> str:
    """取 'v4.5.2 <40位hash>' 这种版本串（判版本只认这个，别信文件名）。"""
    patterns = [rb"v4\.[0-9]+\.[0-9]+ +[0-9a-f]{12,}", rb"v4\.[0-9]+\.[0-9]+"]
    try:
        blob = binary.read_bytes()
    except OSError:
        return "unknown"
    for pat in patterns:
        m = re.search(pat, blob)
        if m:
            return m.group(0).decode("ascii", "replace")
    return "unknown"


def collect(binary: Path) -> tuple[dict[str, int], str]:
    table: dict[str, int] = {}
    source = []
    for dynamic in (True, False):
        try:
            for addr, name in run_nm(binary, dynamic):
                table.setdefault(name, addr)
            source.append(".dynsym" if dynamic else ".symtab")
        except SystemExit:
            raise
        except Exception:
            pass
    return table, "+".join(source)


def autodetect_binary() -> Path | None:
    """没传 binary 参数时：用 find_stellaris 的探测逻辑（环境变量 / satfix.conf / Steam 库）。"""
    if _find_stellaris_dirs is None:
        return None
    for d in _find_stellaris_dirs():
        for name in ("stellaris", "stellaris.exe"):
            exe = d / name
            if exe.is_file():
                return exe
    return None


def render(binary: Path, table: dict[str, int], source: str) -> str:
    import datetime

    def emit(items: list[tuple[str, str, str]]) -> tuple[str, int]:
        rows = []
        hit = 0
        for key, symbol, desc in items:
            addr = table.get(symbol, 0)
            if addr:
                hit += 1
            rows.append(
                '    X({key}, "{sym}", 0x{addr:08x}ull, "{desc}")'.format(
                    key=key, sym=symbol, addr=addr, desc=desc
                )
            )
        return " \\\n".join(rows), hit

    body, found = emit(TARGETS)
    helpers, hfound = emit(HELPERS)
    return HEADER_TEMPLATE.format(
        binary=binary,
        version=game_version(binary),
        when=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source=source,
        found=f"{found}/{len(TARGETS)} targets, {hfound}/{len(HELPERS)} helpers",
        total=len(TARGETS) + len(HELPERS),
        body=body,
        helpers=helpers,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", type=Path, nargs="?", help="stellaris 可执行文件路径；省略则自动探测")
    ap.add_argument("-o", "--output", type=Path, default=None, help="输出头文件路径")
    ap.add_argument("--check", action="store_true", help="只比对现有头文件，不写")
    ap.add_argument("--list", action="store_true", help="只打印解析结果")
    args = ap.parse_args()

    binary = args.binary
    if binary is None:
        binary = autodetect_binary()
        if binary is None:
            sys.exit("没找到群星二进制。请显式传入，或先跑 tools/configure.sh 生成 satfix.conf。")
        print(f"自动探测到: {binary}")
    if not binary.is_file():
        sys.exit(f"二进制不存在: {binary}")
    out_path = args.output or (Path(__file__).resolve().parent.parent / "satfix_targets.generated.hpp")

    table, source = collect(binary)
    text = render(binary, table, source)

    missing = [key for key, sym, _ in (TARGETS + HELPERS) if sym not in table]
    if args.list:
        for key, sym, desc in TARGETS:
            addr = table.get(sym)
            print(f"{'OK ' if addr else 'MISS'}  0x{addr:08x}  {desc}" if addr
                  else f"MISS {'.' * 10}  {desc}  ({sym})")
        print("  ---- 辅助函数（只解析调用，不 hook）----")
        for key, sym, desc in HELPERS:
            addr = table.get(sym)
            print(f"{'OK ' if addr else 'MISS'}  0x{addr:08x}  {desc}" if addr
                  else f"MISS {'.' * 10}  {desc}  ({sym})")
        print(f"\n命中 {len(TARGETS) + len(HELPERS) - len(missing)}/{len(TARGETS) + len(HELPERS)}")
        return 0

    if args.check:
        if not out_path.is_file():
            print(f"没有可比对的文件: {out_path}", file=sys.stderr)
            return 1
        old = out_path.read_text(encoding="utf-8")
        old_addrs = dict(re.findall(r'X\((\w+)\s+"[^"]+",\s*(0x[0-9a-f]+)', old))
        new_addrs = dict(re.findall(r'X\((\w+)\s+"[^"]+",\s*(0x[0-9a-f]+)', text))
        drift = [k for k in set(old_addrs) | set(new_addrs)
                 if old_addrs.get(k) != new_addrs.get(k)]
        if drift:
            print("检测到地址漂移（游戏可能更新过，需要重新生成）：")
            for k in sorted(drift):
                print(f"  {k}: {old_addrs.get(k, 'MISSING')} -> {new_addrs.get(k, 'MISSING')}")
            return 1
        print("地址与当前二进制一致，无需更新。")
        return 0

    out_path.write_text(text, encoding="utf-8")
    print(f"已写入 {out_path}")
    print(f"  命中 {len(TARGETS) - len(missing)}/{len(TARGETS)} 个符号"
          f"（来自 {source}）")
    if missing:
        print("  未命中（会跳过 hook）：" + ", ".join(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
