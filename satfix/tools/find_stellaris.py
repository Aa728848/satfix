#!/usr/bin/env python3
"""自动定位 Stellaris 游戏目录 / 可执行文件。

    tools/find_stellaris.py            # 打印 <game>/stellaris 的路径
    tools/find_stellaris.py --dir      # 打印 <game> 目录
    tools/find_stellaris.py --all      # 列出所有找到的候选

查找顺序：
  1. 环境变量 STELLARIS_BIN / STELLARIS_GAME_DIR
  2. satfix.conf 里的同名变量
  3. 各 Steam 库的 libraryfolders.vdf（含 flatpak / deb 安装位置）
  4. 几个常见硬编码位置（兜底）

找到多个时优先返回第一个，--all 可以看全部。
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

CONF_NAME = "satfix.conf"
REPO_HINT = Path(__file__).resolve().parent.parent

# 常见 Steam 安装位置（含 flatpak）
STEAM_ROOTS = [
    "~/.steam/debian-installation",
    "~/.steam/steam",
    "~/.steam/root",
    "~/.local/share/Steam",
    "~/.var/app/com.valvesoftware.Steam/.local/share/Steam",
    "~/Library/Application Support/Steam",           # macOS
]

# 兜底：直接猜游戏目录
FALLBACK_DIRS = [
    "~/SteamLibrary/steamapps/common/Stellaris",
    "~/.steam/steam/steamapps/common/Stellaris",
    "~/.local/share/Steam/steamapps/common/Stellaris",
    "~/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/common/Stellaris",
]

EXE_NAMES = ("stellaris", "stellaris.exe")


def read_conf() -> dict[str, str]:
    """读 satfix.conf（简单的 KEY=VALUE，支持 # 注释）。"""
    conf: dict[str, str] = {}
    for candidate in (REPO_HINT / CONF_NAME, Path.cwd() / CONF_NAME):
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            conf.setdefault(key.strip(), value)
    return conf


def expand(p: str) -> Path:
    return Path(os.path.expanduser(os.path.expandvars(p)))


def steam_libraries() -> list[Path]:
    libs: list[Path] = []
    for root in STEAM_ROOTS:
        vdf = expand(root) / "steamapps" / "libraryfolders.vdf"
        if not vdf.is_file():
            continue
        try:
            text = vdf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r'"path"\s*"([^"]+)"', text):
            libs.append(Path(m.group(1).replace("\\\\", "/")))
        # 库根自己也算一个
        libs.append(expand(root))
    return libs


def game_dir_from_bin(bin_path: Path) -> Path | None:
    """从可执行文件位置反推游戏目录。"""
    if bin_path.name.lower() in EXE_NAMES and bin_path.is_file():
        return bin_path.parent
    if bin_path.is_dir():
        for name in EXE_NAMES:
            if (bin_path / name).is_file():
                return bin_path
    return None


def find_all() -> list[Path]:
    found: list[Path] = []

    def push(p: Path | None):
        if p and p.is_dir() and p not in found:
            found.append(p)

    conf = read_conf()
    for key in ("STELLARIS_BIN", "STELLARIS_GAME_DIR"):
        val = os.environ.get(key) or conf.get(key)
        if val:
            push(game_dir_from_bin(expand(val)))

    for lib in steam_libraries():
        push(lib / "steamapps" / "common" / "Stellaris")

    for d in FALLBACK_DIRS:
        push(expand(d))

    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", action="store_true", help="打印游戏目录而不是可执行文件")
    ap.add_argument("--all", action="store_true", help="列出全部候选")
    args = ap.parse_args()

    dirs = find_all()
    if not dirs:
        print("没找到 Stellaris 安装目录。请手动设置：", file=sys.stderr)
        print("    tools/configure.sh /path/to/Stellaris", file=sys.stderr)
        return 1

    if args.all:
        for d in dirs:
            mark = "  " if any((d / n).is_file() for n in EXE_NAMES) else "无"
            print(f"{mark} {d}")
        return 0

    for d in dirs:
        for name in EXE_NAMES:
            exe = d / name
            if exe.is_file():
                print(d if args.dir else exe)
                return 0

    print(f"找到了目录但里面没有 {' / '.join(EXE_NAMES)}：{dirs[0]}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
