"""Caller-side check: read the call targets out of a relocated function and
compare with the 4.5.2 original, using the already-relocated callees as anchors.

This is the "look at the call site" discipline from AGENTS.md section 2: identity
of a callee is established by who calls it and in what order, not by guessing.
"""
import json
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const

EXE = r"D:\Steam\steamapps\common\Stellaris\stellaris.exe"
OLD = r"C:\Users\A\Documents\ChatGPT\anti_stellaris\stellaris-overflow\satfix-win\tools\relocate\old_bytes_452.json"
IMAGE_BASE = 0x140000000

NEW = {
    "access_var_pointer": 0x009F99B0,
    "cvars_get": 0x002272C0,
    "cvars_set": 0x007AC110,
    "cfp_getvalue?": 0x0034DF70,
    "cfp_getvalue?2": 0x0034E790,
    "cfp_getvalue?3": 0x0034F1E0,
    "cfp_getvalue?4": 0x0034D4C0,
    "ship_size_of": 0x0030F330,
    "modifier_value": 0x00D2F160,
    "var_multiply": 0x0177C660,
    "var_add": 0x0177BF60,
}

pe = pefile.PE(EXE, fast_load=True)
text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text").get_data()
old = json.loads(open(OLD, encoding="utf-8").read())["targets"]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def calls(code, va):
    out = []
    for insn in md.disasm(code, va):
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == x86_const.X86_OP_IMM:
            out.append(insn.operands[0].imm)
    return out


key = "var_multiply"
old_calls = calls(bytes.fromhex(old[key]["bytes"]), old[key]["entry_va"])
new_calls = calls(text[NEW[key] - 0x1000: NEW[key] - 0x1000 + old["var_multiply"]["size"]], IMAGE_BASE + NEW[key])
print("old call count", len(old_calls), "new call count", len(new_calls))
for i, (a, b) in enumerate(zip(old_calls, new_calls)):
    a_rva = a - IMAGE_BASE
    b_rva = b - IMAGE_BASE
    label = ""
    for name, r in NEW.items():
        if r == b_rva:
            label = "-> " + name
    print("  [%2d] old 0x%08X (%+#x vs old func)  new 0x%08X %s" % (i, a_rva, a_rva - old[key]["rva"], b_rva, label))

# 同时看 cfp_getvalue 家族的四个候选都有哪些调用者，用调用者个数区分
print()
for name, rva in list(NEW.items()):
    if not name.startswith("cfp_getvalue"):
        continue
    print(name, hex(rva))
