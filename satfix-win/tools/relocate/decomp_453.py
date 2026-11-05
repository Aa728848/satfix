"""Independent verification: decompile the 4.5.3 functions at the new RVAs and
compare them against the 4.5.2 decompiled bodies.

This does not reuse the byte scan at all -- Ghidra re-identifies the function at
the address and gives a fresh decompilation, so the comparison is semantic.
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

PROJ_DIR = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\_analysis\stellaris-c453"
PROJ_NAME = "stellaris-c453"
OUT = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\decomp_453.json"
IMAGE_BASE = 0x140000000

TARGETS = {
    "cfx_get_rounded": 0x01B50CE0, "cfx_to_fp15": 0x01B50C10, "cfx_get_rounded_fp15": 0x01B50C70,
    "cfx_round_to": 0x01B50D20, "cfx_atan2": 0x01B50E40, "cfx_sqrt": 0x01B4D540, "cfx_safe_sqrt": 0x01B51170,
    "apply_mul_cfx": 0x0036E990, "apply_mul_fp15": 0x0036EAB0,
    "hull_max": 0x00A152E0, "shield_max": 0x00A15DC0, "armor_max": 0x00A16950,
    "damage_per_day": 0x00A18CA0, "mpe15": 0x00A0E4E0, "mpe7": 0x00A0E650,
    "var_add": 0x0177BF60, "var_multiply": 0x0177C660,
    "diplo_weight": 0x00839B40, "ship_size_max_hp": 0x00D30A70,
    "access_var_pointer": 0x009F99B0, "cvars_get": 0x002272C0, "cvars_set": 0x007AC110,
    "cfp_getvalue": 0x0034DF70, "ship_size_of": 0x0030F330, "modifier_value": 0x00D2F160,
}


def main() -> int:
    from pyghidra import HeadlessPyGhidraLauncher
    HeadlessPyGhidraLauncher().start()
    from pyghidra.api import open_project, program_context
    from java.lang import Object  # noqa: F401

    proj = open_project(PROJ_DIR, PROJ_NAME)
    result = {"program": None, "targets": {}}
    with program_context(proj, "/stellaris.exe") as prog:
        result["program"] = prog.getName()
        fm = prog.getFunctionManager()
        from ghidra.app.decompiler import DecompInterface
        dec = DecompInterface()
        dec.openProgram(prog)
        res = dec.openProgram(prog)
        print("[dec] decompiler:", res, flush=True)
        af = prog.getAddressFactory().getDefaultAddressSpace()
        for key, rva in TARGETS.items():
            va = IMAGE_BASE + rva
            addr = af.getAddress(va)
            fn = fm.getFunctionAt(addr)
            entry_ok = fn is not None
            if fn is None:
                fn = fm.getFunctionContaining(addr)
            rec = {"rva": rva, "is_function_entry": entry_ok}
            if fn is None:
                rec["error"] = "no function"
                result["targets"][key] = rec
                print(f"[dec] {key}: no function at {hex(va)}", flush=True)
                continue
            rec["ghidra_function"] = fn.getName()
            rec["ghidra_entry_rva"] = fn.getEntryPoint().getOffset() - IMAGE_BASE
            rec["size"] = int(fn.getBody().getNumAddresses())
            dres = dec.decompileFunction(fn, 60, None)
            if dres and dres.decompileCompleted():
                src = dres.getDecompiledFunction().getC()
                rec["decompiled"] = src
                rec["lines"] = src.count("\n") + 1
            else:
                rec["error"] = "decompile failed"
            result["targets"][key] = rec
            print(f"[dec] {key:22s} entry={entry_ok} rva=0x{rec.get('ghidra_entry_rva', 0):08X} "
                  f"size={rec.get('size', 0):5d} lines={rec.get('lines', 0)}", flush=True)
        dec.dispose()

    Path = __import__("pathlib").Path
    Path(OUT).write_text(json.dumps(result, indent=1), encoding="utf-8")
    print("[dec] wrote", OUT, flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
