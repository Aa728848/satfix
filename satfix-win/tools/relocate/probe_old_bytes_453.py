#!/usr/bin/env python
"""Probe: read 4.5.3 target function bytes out of the Ghidra project stellaris-c453.

Read-only. Same idea as probe_old_bytes.py (which did 4.5.2), but the target list
is parsed from the repo itself so it can never drift from the shipped table:
  - CONFIRMED  <- src/satfix_targets_win.generated.hpp  (the 4.5.3 generated table)
  - HELPERS    <- tools/gen_targets_win.py

Output: old_bytes_453.json  {project, program, functionCount, targets:{key:{rva,size,bytes}}}
"""
import json
import os
import re
import sys
import traceback

GHIDRA = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\vendor\ghidra_12.1.4_PUBLIC"
JAVA = r"C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot"
os.environ.setdefault("GHIDRA_INSTALL_DIR", GHIDRA)
os.environ.setdefault("JAVA_HOME", JAVA)
os.environ["PATH"] = os.path.join(JAVA, "bin") + os.pathsep + os.environ.get("PATH", "")

ROOT = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win"
PROJ_DIR = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\_analysis\stellaris-c453"
PROJ_NAME = "stellaris-c453"
OUT = os.path.join(ROOT, "tools", "relocate", "old_bytes_453.json")
IMAGE_BASE = 0x140000000


def load_targets():
    hpp = open(os.path.join(ROOT, "src", "satfix_targets_win.generated.hpp"), encoding="utf-8").read()
    conf = []
    for m in re.finditer(r'\{\s*"(\w+)",\s*"[^"]*",\s*(0x[0-9a-fA-F]+)u,\s*kSig_', hpp):
        conf.append((m.group(1), int(m.group(2), 16), "hook"))
    py = open(os.path.join(ROOT, "tools", "gen_targets_win.py"), encoding="utf-8").read()
    blk = py.split("HELPERS: list", 1)[1]
    helpers = []
    for m in re.finditer(r'"([a-z_0-9]+)",\s*\n\s*"[^"]*",\s*\n\s*(0x[0-9A-Fa-f]+),', blk):
        helpers.append((m.group(1), int(m.group(2), 16), "helper"))
    return conf + helpers


def read_bytes(mem, start, size):
    raw = bytearray()
    addr = start
    left = size
    while left > 0:
        if left >= 4:
            raw += (mem.getInt(addr) & 0xFFFFFFFF).to_bytes(4, "little")
            addr = addr.add(4)
            left -= 4
        elif left >= 2:
            raw += (mem.getShort(addr) & 0xFFFF).to_bytes(2, "little")
            addr = addr.add(2)
            left -= 2
        else:
            raw.append(mem.getByte(addr) & 0xFF)
            addr = addr.add(1)
            left -= 1
    return bytes(raw)


def main() -> int:
    targets = load_targets()
    print(f"[probe] {len(targets)} targets parsed from repo", flush=True)
    from pyghidra import HeadlessPyGhidraLauncher
    HeadlessPyGhidraLauncher().start()
    from pyghidra.api import open_project, program_context

    proj = open_project(PROJ_DIR, PROJ_NAME)
    root = proj.getProjectData().getRootFolder()
    files = list(root.getFiles())
    print("[probe] project files:", [(f.getName(), f.getPathname()) for f in files], flush=True)
    if not files:
        print("[probe] FAIL: project has no program files", flush=True)
        return 2
    target_file = files[0].getPathname()
    for f in files:
        if "stellaris.exe" in f.getName():
            target_file = f.getPathname()

    result = {"project": PROJ_NAME, "program": target_file, "targets": {}}
    with program_context(proj, target_file) as prog:
        mem = prog.getMemory()
        fm = prog.getFunctionManager()
        result["functionCount"] = fm.getFunctionCount()
        print("[probe] program =", prog.getName(), "funcs =", fm.getFunctionCount(), flush=True)
        space = prog.getAddressFactory().getDefaultAddressSpace()
        for key, rva, kind in targets:
            va = IMAGE_BASE + rva
            rec = {"rva": rva, "va": va, "kind": kind}
            try:
                fn = fm.getFunctionContaining(space.getAddress(va))
                if fn is None:
                    rec["error"] = "no function at address"
                    print(f"[probe] {key}: NO FUNCTION at {hex(va)}", flush=True)
                    result["targets"][key] = rec
                    continue
                size = int(fn.getBody().getNumAddresses())
                rec.update({"name": fn.getName(), "entry_va": fn.getEntryPoint().getOffset(), "size": size})
                rec["start_ok"] = rec["entry_va"] == va
                body = read_bytes(mem, fn.getEntryPoint(), size)
                rec["bytes"] = body.hex()
                print(f"[probe] {key:22s} {fn.getName():20s} size={size:5d} start_ok={rec['start_ok']}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[probe] {key}: EXC {exc}", flush=True)
                rec["error"] = str(exc)
            result["targets"][key] = rec

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1)
    print("[probe] wrote", OUT, flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
