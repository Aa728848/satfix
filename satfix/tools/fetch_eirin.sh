#!/usr/bin/env bash
#
# 从 GitHub release 拉取 EirinMath 到 satfix/third_party/
#
#   tools/fetch_eirin.sh              # 拉最新 release
#   tools/fetch_eirin.sh 1.5.2        # 拉指定版本
#   tools/fetch_eirin.sh --list       # 只看有哪些 release
#
# 需要联网。拉完 build.sh 会自动优先使用 third_party 里的那份。
#
set -euo pipefail

REPO="Koishi-Satori/EirinMath"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$HERE/third_party"

if [ "${1:-}" = "--list" ]; then
    curl -sSL "https://api.github.com/repos/$REPO/releases?per_page=20" \
        | grep -E '"tag_name"|"published_at"' | paste - - | sed 's/^\s*//'
    exit 0
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "==> 查询最新 release…"
    VERSION="$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')"
fi
if [ -z "$VERSION" ]; then
    echo "未能确定版本号，请手动指定，例如: $0 1.5.2" >&2
    exit 1
fi

DEST="$TP/EirinMath-$VERSION"
if [ -d "$DEST" ]; then
    echo "==> $DEST 已存在，跳过下载"
    exit 0
fi

echo "==> 下载 EirinMath v$VERSION"
mkdir -p "$TP"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -sSL -o "$TMP/eirinmath.tar.gz" \
    "https://github.com/$REPO/archive/refs/tags/v$VERSION.tar.gz"

echo "==> 解压到 $TP"
tar xzf "$TMP/eirinmath.tar.gz" -C "$TP"

if [ ! -f "$DEST/include/eirin/numeric.hpp" ]; then
    echo "解压后没找到 $DEST/include/eirin/numeric.hpp，请检查包结构" >&2
    exit 1
fi
echo "==> 完成：$DEST/include"
echo "    重新构建：$HERE/build.sh"
