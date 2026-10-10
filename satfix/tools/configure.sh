#!/usr/bin/env bash
#
# 生成 satfix.conf —— 把群星安装位置等本地路径固化下来
#
#   tools/configure.sh                     # 自动探测并写配置
#   tools/configure.sh /path/to/Stellaris  # 手动指定游戏目录
#   tools/configure.sh --show              # 只看当前生效的配置
#   tools/configure.sh --clean             # 删掉 satfix.conf，回到自动探测
#
# build.sh / gen_targets.py 都会读这份配置；环境变量优先级更高，
# 所以临时覆盖不需要改文件：
#   BIN=/other/stellaris STELLARIS_GAME_DIR=/other ./build.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$HERE/satfix.conf"
FIND="$HERE/tools/find_stellaris.py"

case "${1:-}" in
    --clean)
        rm -f "$CONF"
        echo "已删除 $CONF（build.sh 会退回自动探测）"
        exit 0
        ;;
    --show)
        echo "配置文件: $CONF $([ -f "$CONF" ] && echo '(存在)' || echo '(不存在)')"
        [ -f "$CONF" ] && { echo "----"; cat "$CONF"; echo "----"; }
        echo "自动探测: $(python3 "$FIND" 2>/dev/null || echo '未找到')"
        echo "生效值  : BIN=${BIN:-<未设置>} STELLARIS_GAME_DIR=${STELLARIS_GAME_DIR:-<未设置>}"
        exit 0
        ;;
esac

# 解析目标游戏目录
if [ -n "${1:-}" ]; then
    GAME_DIR="$1"
else
    GAME_DIR="$(python3 "$FIND" --dir)" || {
        echo "自动探测失败。用法：$0 /path/to/Stellaris" >&2
        exit 1
    }
    echo "自动探测到: $GAME_DIR"
fi

if [ ! -d "$GAME_DIR" ]; then
    echo "目录不存在: $GAME_DIR" >&2
    exit 1
fi

BIN_PATH=""
for name in stellaris stellaris.exe; do
    if [ -f "$GAME_DIR/$name" ]; then
        BIN_PATH="$GAME_DIR/$name"
        break
    fi
done
if [ -z "$BIN_PATH" ]; then
    echo "在 $GAME_DIR 里没找到 stellaris 可执行文件" >&2
    echo "（如果你指的是别的目录，直接传游戏根目录）" >&2
    exit 1
fi

cat > "$CONF" <<EOF
# satfix 本地配置 —— 由 tools/configure.sh 生成，可以随时删掉重来
# 这些是"默认值"；用环境变量（BIN / EIRIN_INC / HOOKLIB / GEN）可以临时覆盖。

STELLARIS_GAME_DIR=$GAME_DIR
STELLARIS_BIN=$BIN_PATH

# eirin 头文件目录，留空表示按 build.sh 的优先级自动挑
# （third_party/*/include > 本地开发仓库）
# EIRIN_INC=

# hooklib（shk.hpp）所在目录，留空表示 \$HERE/../hooklib
# HOOKLIB=
EOF

echo "已写入 $CONF"
echo "  STELLARIS_GAME_DIR=$GAME_DIR"
echo "  STELLARIS_BIN=$BIN_PATH"
if command -v file >/dev/null 2>&1; then
    echo "  二进制: $(file -b "$BIN_PATH" | cut -c1-80)"
fi
echo
echo "下一步: $HERE/build.sh"
