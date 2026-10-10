#!/usr/bin/env bash
# 编译 satfix 的两块东西
#
#   ./build.sh          默认：影子模式（只观测，不改数值）
#   ./build.sh replace  打开"溢出时回写饱和值"
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# 配置：环境变量 > satfix.conf > 自动探测
#   tools/configure.sh           生成 satfix.conf（把群星目录固化下来）
#   tools/configure.sh --show    看当前生效的值
# 不写死任何路径，换机器/换 Steam 库都不用改脚本。
# ---------------------------------------------------------------------------
CONF="$HERE/satfix.conf"

# 先记住环境变量，source 配置文件之后再恢复 —— 保证"环境变量优先级更高"
_env_bin="${BIN:-}"; _env_eirin="${EIRIN_INC:-}"; _env_hooklib="${HOOKLIB:-}"; _env_gen="${GEN:-}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"
[ -n "$_env_bin" ]     && BIN="$_env_bin"
[ -n "$_env_eirin" ]   && EIRIN_INC="$_env_eirin"
[ -n "$_env_hooklib" ] && HOOKLIB="$_env_hooklib"
[ -n "$_env_gen" ]     && GEN="$_env_gen"

BIN="${BIN:-${STELLARIS_BIN:-}}"
if [ -z "$BIN" ]; then
    BIN="$(python3 "$HERE/tools/find_stellaris.py" 2>/dev/null || true)"
fi
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "找不到群星二进制。任选一种方式：" >&2
    echo "  1) $HERE/tools/configure.sh            # 自动探测并写 satfix.conf" >&2
    echo "  2) $HERE/tools/configure.sh /path/to/Stellaris" >&2
    echo "  3) BIN=/path/to/stellaris $0" >&2
    exit 1
fi

HOOKLIB="${HOOKLIB:-$HERE/../hooklib}"
GEN="${GEN:-0}"

# eirin 头文件位置，优先级：
#   1) 环境变量 EIRIN_INC
#   2) satfix/third_party/<EirinMath-x.y.z>/include（tools/fetch_eirin.sh 拉取）
#   3) 本地开发仓库 $EIRIN_DEV_REPO（默认 $HOME/CLionProjects/fixed32）
EIRIN_DEV_REPO="${EIRIN_DEV_REPO:-$HOME/CLionProjects/fixed32}"
if [ -z "${EIRIN_INC:-}" ]; then
    EIRIN_INC="$(ls -d "$HERE"/third_party/*/include 2>/dev/null | head -1)"
    if [ -n "$EIRIN_INC" ]; then
        EIRIN_SRC="third_party"
    else
        EIRIN_INC="$EIRIN_DEV_REPO/include"
        EIRIN_SRC="local dev repo ($EIRIN_DEV_REPO)"
    fi
fi
if [ ! -f "$EIRIN_INC/eirin/numeric.hpp" ]; then
    echo "找不到 eirin/numeric.hpp（EIRIN_INC=$EIRIN_INC）" >&2
    echo "先跑 tools/fetch_eirin.sh 拉取 release，或设 EIRIN_INC 指向正确位置" >&2
    exit 1
fi

REPLACE=0
if [ "${1:-}" = "replace" ]; then
    REPLACE=1
fi

echo "==> eirin include : $EIRIN_INC${EIRIN_SRC:+  ($EIRIN_SRC)}"
echo "==> hooklib       : $HOOKLIB"
echo "==> 群星二进制   : $BIN"
echo "==> 配置文件     : $CONF $([ -f "$CONF" ] && echo '(已生效)' || echo '(未生成，可跑 tools/configure.sh)')"
echo "==> SATFIX_REPLACE: $REPLACE"

if [ "$GEN" = "1" ]; then
    echo "==> 重新生成 hook 目标地址"
    python3 "$HERE/tools/gen_targets.py" "$BIN"
elif [ -f "$HERE/satfix_targets.generated.hpp" ]; then
    echo "==> 校验 hook 目标地址是否漂移（GEN=1 可强制重新生成）"
    python3 "$HERE/tools/gen_targets.py" "$BIN" --check || {
        echo "    ↑ 检测到漂移，正在重新生成…"
        python3 "$HERE/tools/gen_targets.py" "$BIN"
    }
else
    echo "==> 首次生成 hook 目标地址"
    python3 "$HERE/tools/gen_targets.py" "$BIN"
fi

echo "==> 编译离线对拍测试"
g++ -O2 -std=c++20 -I"$HERE" -I"$EIRIN_INC" -o "$HERE/test_stl_fix" "$HERE/test_stl_fix.cpp"

echo "==> 编译 hook 动态库"
g++ -O2 -std=c++20 -shared -fPIC -DSATFIX_REPLACE="$REPLACE" \
    -I"$HERE" -I"$HOOKLIB" -I"$EIRIN_INC" \
    -o "$HERE/sat_guard.so" "$HERE/sat_guard.cpp" -ldl

echo "==> ABI / 影子逻辑回归（用假符号，不需要开游戏）"
if ! "$HERE/test/run_abi_check.sh" "$HERE/sat_guard.so" > /tmp/satfix_abi_check.log 2>&1; then
    echo
    echo "!! ABI 回归失败，详情："
    tail -30 /tmp/satfix_abi_check.log
    echo
    echo "先修好这个再进游戏 —— 否则 hook 要么写坏返回值，要么影子数据全是垃圾。"
    exit 1
fi
echo "    ABI 回归通过（$(grep -o '安全输入下的 EVENT 数: [0-9]*' /tmp/satfix_abi_check.log))"

echo
echo "完成："
echo "  $HERE/test_stl_fix   （先跑这个，必须全过）"
echo "  $HERE/sat_guard.so   （LD_PRELOAD 用）"
echo
echo "启动："
echo "  cd $(dirname "$BIN")"
echo "  LD_PRELOAD=$HERE/sat_guard.so ./stellaris"
echo
echo "（Steam 启动的话，在 launch options 里写：）"
echo "  LD_PRELOAD=$HERE/sat_guard.so %command%"
