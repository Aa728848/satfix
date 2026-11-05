#!/usr/bin/env python
"""Probe: read 4.5.2 target function bytes out of the existing Ghidra project.

Read-only. Prints per-target: function name, entry VA, size, and the raw bytes
(as hex) of the function body, so we can build masked signatures and scan the
new (4.5.3) exe for the same bodies.
"""
import json
import os
import sys
import traceback

GHIDRA = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\vendor\ghidra_12.1.4_PUBLIC"
JAVA = r"C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot"
os.environ.setdefault("GHIDRA_INSTALL_DIR", GHIDRA)
os.environ.setdefault("JAVA_HOME", JAVA)
os.environ["PATH"] = os.path.join(JAVA, "bin") + os.pathsep + os.environ.get("PATH", "")

PROJ_DIR = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\_analysis\stellaris-c452"
PROJ_NAME = "stellaris-c452"
OUT = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\old_bytes_452.json"

TARGETS = [
    ("cfx_get_rounded", 0x01B4C170),
    ("cfx_to_fp15", 0x01B4C0A0),
    ("apply_mul_cfx", 0x0036DF80),
    ("apply_mul_fp15", 0x0036E0A0),
    ("cfx_round_to", 0x01B4C1B0),
    ("cfx_atan2", 0x01B4C2D0),
    ("var_multiply", 0x01777F00),
    ("var_add", 0x01777800),
    ("cfx_get_rounded_fp15", 0x01B4C100),
    ("shield_max", 0x00A11D80),
    ("armor_max", 0x00A12910),
    ("hull_max", 0x00A112A0),
    ("cfx_sqrt", 0x01B489D0),
    ("cfx_safe_sqrt", 0x01B4C600),
    ("diplo_weight", 0x00838670),
    ("mpe15", 0x00A0A4A0),
    ("mpe7", 0x00A0A610),
    ("damage_per_day", 0x00A14C60),
    ("ship_size_max_hp", 0x00D2B6E0),
    # --- 辅助函数（HELPERS 表，只解析地址不装钩子）---
    ("access_var_pointer", 0x009F7DF0),
    ("cvars_get", 0x00227390),
    ("cvars_set", 0x007AAE10),
    ("cfp_getvalue", 0x0034D500),
    ("ship_size_of", 0x0030E990),
    ("modifier_value", 0x00D29DD0),
]
IMAGE_BASE = 0x140000000


def main() -> int:
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
        print("[probe] program =", prog.getName(), flush=True)
        mem = prog.getMemory()
        fm = prog.getFunctionManager()
        nfun = fm.getFunctionCount()
        print("[probe] functionCount =", nfun, flush=True)
        result["functionCount"] = nfun
        for key, rva in TARGETS:
            va = IMAGE_BASE + rva
            try:
                from ghidra.program.model.address import AddressSetView
                addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(va)
                fn = fm.getFunctionContaining(addr)
                rec = {"rva": rva, "va": va}
                if fn is None:
                    rec["error"] = "no function at address"
                    print(f"[probe] {key}: NO FUNCTION at {hex(va)}", flush=True)
                    result["targets"][key] = rec
                    continue
                entry = fn.getEntryPoint().getOffset()
                body = fn.getBody()
                size = int(body.getNumAddresses())
                rec.update({
                    "name": fn.getName(),
                    "entry_va": entry,
                    "size": size,
                    "start_matches_rva": entry == va,
                })
                raw = bytearray()
                try:
                    raise RuntimeError("force chunked read")
                except Exception:
                    # mem.getBytes() cannot fill a python bytearray through pyghidra,
                    # so read dwords with getInt() and unpack little-endian.
                    addr_i = fn.getEntryPoint()
                    left = size
                    while left > 0:
                        if left >= 4:
                            v = mem.getInt(addr_i) & 0xFFFFFFFF
                            raw += v.to_bytes(4, "little")
                            addr_i = addr_i.add(4)
                            left -= 4
                        elif left >= 2:
                            v = mem.getShort(addr_i) & 0xFFFF
                            raw += v.to_bytes(2, "little")
                            addr_i = addr_i.add(2)
                            left -= 2
                        else:
                            raw.append(mem.getByte(addr_i) & 0xFF)
                            addr_i = addr_i.add(1)
                            left -= 1
                rec["bytes"] = bytes(raw).hex()
                got = len(raw)
                print(f"[probe] {key}: {fn.getName()} entry={hex(entry)} size={size} got={got}", flush=True)
                result["targets"][key] = rec
            except Exception as exc:  # noqa: BLE001
                print(f"[probe] {key}: EXC {exc}", flush=True)
                result["targets"][key] = {"rva": rva, "error": str(exc)}

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
