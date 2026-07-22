#!/usr/bin/env python3
"""
setup_build_id.py - 扫描 ELF 文件，建立 .build-id 符号链接

约定 (gdb/perf/pwndbg 一致):
  .build-id/xx/yyyyyyyyyyyyyy.debug -> 相对路径指向实际 ELF 文件
  其中 xx = build-id 前 2 字符, yyyy = 剩余字符

用法:
  cd <题目目录>
  python3 .debug/setup_build_id.py [debug_dir]

不传参数时默认扫描当前目录下的 .debug/ 目录。
"""

import os
import sys
import re
import subprocess


def get_build_id(path: str) -> str | None:
    """用 readelf -n 提取 ELF 的 build-id"""
    try:
        result = subprocess.run(
            ["readelf", "-n", path],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"Build ID:\s+([a-f0-9]+)", result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def is_elf(path: str) -> bool:
    """快速判断是否为 ELF 文件"""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def setup_build_id(debug_dir: str) -> tuple[int, int]:
    """
    扫描 debug_dir 下所有 ELF 文件，在 debug_dir/.build-id/ 中建立符号链接。
    返回 (新建数, 跳过数)。
    """
    buildid_dir = os.path.join(debug_dir, ".build-id")
    count = 0
    skip = 0

    for root, dirs, files in os.walk(debug_dir):
        # 跳过 .build-id 自身
        if os.path.commonpath([root, buildid_dir]) == buildid_dir:
            continue
        dirs[:] = [d for d in dirs if not d.startswith(".build-id")]

        for name in files:
            fpath = os.path.join(root, name)
            if not is_elf(fpath):
                continue

            bid = get_build_id(fpath)
            if not bid:
                continue

            prefix = bid[:2]
            suffix = bid[2:]
            link_dir = os.path.join(buildid_dir, prefix)
            link_path = os.path.join(link_dir, f"{suffix}.debug")

            os.makedirs(link_dir, exist_ok=True)

            if os.path.lexists(link_path):
                skip += 1
                continue

            rel = os.path.relpath(fpath, link_dir)
            os.symlink(rel, link_path)
            count += 1
            print(f"[LINK] {bid} -> {fpath}")

    return count, skip


def main():
    debug_dir = sys.argv[1] if len(sys.argv) > 1 else ".debug"
    debug_dir = os.path.abspath(debug_dir)

    if not os.path.isdir(debug_dir):
        print(f"Error: '{debug_dir}' not found", file=sys.stderr)
        sys.exit(1)

    count, skip = setup_build_id(debug_dir)
    print(f"\nDone. Created {count} new symlinks, skipped {skip} existing.")
    print(f"Build-id directory: {os.path.join(debug_dir, '.build-id')}")


if __name__ == "__main__":
    main()
