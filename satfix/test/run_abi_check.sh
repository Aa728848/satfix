#!/usr/bin/env bash
#
# 离线回归：用假符号验证 sat_guard 的 hook 装得上、ABI 没写错、影子模式不误报。
#
#   test/run_abi_check.sh [sat_guard.so 路径]
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SATFIX="$(cd "$HERE/.." && pwd)"
GUARD="${1:-$SATFIX/sat_guard.so}"

if [ ! -f "$GUARD" ]; then
    echo "找不到 $GUARD，先跑 $SATFIX/build.sh" >&2
    exit 1
fi

cd "$HERE"
echo "==> 编译 mock"
g++ -O2 -std=c++20 -shared -fPIC -o libmock_stellaris.so mock_stellaris.cpp

echo "==> 编译 driver"
g++ -O2 -std=c++20 -o abi_check abi_check.cpp -ldl

echo "==> 跑（stdout=断言，stderr=sat_guard 的日志）"
set +e
# SATFIX_FORCE=1: 绕过"只对 stellaris 进程生效"的检查（这里是假游戏进程）
SATFIX_FORCE=1 ./abi_check ./libmock_stellaris.so "$GUARD" > /tmp/abi_check.out 2> /tmp/abi_check.err
RC=$?
set -e

cat /tmp/abi_check.out

echo
echo "==> sat_guard 在 mock 上装了几个 hook"
grep -c "hooked " /tmp/abi_check.err || true

EVENTS=$(grep -c "EVENT" /tmp/abi_check.err || true)
echo "==> 安全输入下的 EVENT 数: $EVENTS （应为 0，否则说明影子逻辑/ABI 有问题）"

if [ "$EVENTS" != "0" ]; then
    echo
    echo "---- 误报样例 ----"
    grep "EVENT" /tmp/abi_check.err | head -5
    echo "------------------"
fi

if [ "$RC" != "0" ] || [ "$EVENTS" != "0" ]; then
    echo
    echo "结果：失败"
    exit 1
fi

echo
echo "结果：通过（ABI 正确、影子模式在安全输入下无输出）"
