#!/usr/bin/env python3
"""生成 satfix-win 的 Windows 目标表（RVA + 序言签名）。

背景：为什么 Windows 侧不能照抄 Linux 的定位方式
----------------------------------------------
Linux 版（`satfix/tools/gen_targets.py`）用 `nm` 拿到 mangled 名 -> 地址，
运行时再 `dlsym` / 读 `/proc/self/exe` 的符号表。

Windows 的 `stellaris.exe` 实测：
  * **没有 PDB**
  * 导出表只有 **110 个符号**（全是 CRT/导出转发的边角），**没有任何 C++ 符号**
  * 因此 `GetProcAddress` 拿不到 `CFixedPoint::GetRounded` 之类

所以 Windows 侧换成：**硬编码 RVA + 序言字节签名双重校验**。

  1. RVA 从静态分析得出（见下）；
  2. 运行时先按 RVA 读前 N 字节，与签名逐字节比对；
  3. 比对失败（游戏更新过 / 读不到）就**安全停用该目标并写日志**，
     绝不盲目读写内存（PLUGIN_HANDBOOK 6.4、7 节的要求）。

序言签名同时管住了两件事：RVA 漂移，以及"注入到了不是这个构建的游戏上"。

本脚本 `--check` 用同一份签名去校验目标 exe，等于把运行时的自检提前到构建期。

目标是怎么确认的
----------------
不用 `_analysis/win_linux_mapping_final_452.json` 的函数名当证据 —— 那份映射是
**字符串字面量指纹**匹配出来的，`confidence: exact` 只表示"字符串指纹唯一命中"，
**不等于**函数身份。实测反例：

  * `FUN_1408b3700` 标为 `ApplyModifierMult`，实际是 modifier token 分发器
    （把 `param_3` 与 0x2a7b/0xb5/0x31a 比较）；
  * `FUN_1408b3e00` 标为 `ApplyModifierMult`，实际是**析构函数**。

本表用的是**函数体形状确证**（定点算术的常量 + 运算符 + 调用形状），
逐条证据写在下面每个目标的 `evidence` 里，可直接用
`tools/win_dump_index.py --fun <FUN_> --body` 复核。
比对基准是 Linux 反编译（两侧 build hash 逐字节相同：
32709cf254181b032b1b309a6ea09776）。

用法::

    tools/gen_targets_win.py --check      # 校验现有头文件里的 RVA/签名是否仍匹配 exe
    tools/gen_targets_win.py              # 重新生成 src/satfix_targets_win.generated.hpp
    tools/gen_targets_win.py --exe <path>
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover
    sys.exit("需要 pefile：python -m pip install pefile")

DEFAULT_EXE = r"D:\Steam\steamapps\common\Stellaris\stellaris.exe"
IMAGE_BASE = 0x140000000
SIG_LEN = 16

# 策略（与 Linux 版的三分类一致，另加一个安全失败态）
STRAT_EXACT = "EXACT"              # 有精确饱和参考实现，可逐位比对、可替换
STRAT_INPUT_GUARD = "INPUT_GUARD"  # 危险在输入域：先把输入夹到安全域再调原函数
STRAT_OBSERVE = "OBSERVE"          # 只能判定"是否进入危险域"，只记日志
STRAT_DISABLED = "DISABLED"        # 地址已确证但 ABI 未确认：拒绝安装（安全失败）

# ---------------------------------------------------------------------------
# 已确证的目标
#
# (key, 可读名, RVA, 策略, 证据)
#
# 确认过的 RVA；签名由脚本从 exe 读出（不手打，避免抄错）。
# ---------------------------------------------------------------------------
CONFIRMED: list[tuple[str, str, int, str, str]] = [
    (
        "cfx_get_rounded",
        "CFixedPoint::GetRounded() const  /  GetRounded64() const",
        0x01B4C170,
        STRAT_EXACT,
        "win dump FUN_141b4c170（17 行）："
        "lVar1=*p1; lVar2=lVar1-50000; if(-1<lVar1) lVar2=lVar1+50000; return lVar2/100000; "
        "与 Linux 的 CFixedPoint::GetRounded/GetRounded64（反编译 8599412/8599430，两函数体**完全相同**）"
        "逐字一致。MSVC 的 COMDAT 折叠把这两个相同函数合并成了一份，所以只有一个地址 —— "
        "这与「脚本里查 GetRounded 得 0 命中、GetRounded 形状的孪生只有 1 个」互相印证。"
        "已实测溢出：INT64_MAX -> 游戏得 -92233720368547，饱和版 +92233720368547。",
    ),
    (
        "cfx_to_fp15",
        "CFixedPoint::operator fpml::fixed_point<long long,48,15>() const",
        0x01B4C0A0,
        STRAT_EXACT,
        "**ABI 靠调用点确证，不是靠猜**。同族有两个实例，签名不同："
        "(a) FUN_141b4c0a0：*param_2 = ((*param_1 % 100000)*0x40000000)/0xc3500000 "
        "+ (*param_1/100000)*0x8000；调用点 `FUN_141b4c0a0(&DAT_1431517c8, local_368)` —— "
        "**目标是第二个参数**（rbx 里的 sret 槽），源在 rcx（this）。"
        "这正是 CFixedPoint::operator fpml<...,15>() const（Linux 反编译 8599274）。"
        "(b) FUN_14075a370：*param_1 = ((param_2 % 100000)*0x40000000)/0xc3500000 "
        "+ (param_2/100000)*0x8000；调用点 `FUN_14075a370(&local_res20, 1000)` —— "
        "**第二个参数是标量**（1000/10000/100000/1000000），所以它是另一个带**缩放参数**的"
        "换算（反方向：把某个定点值换成另一种刻度），**不是** operator fpml。"
        "我最初把 0x75A370 当成 operator fpml 并按「rdx 传值」写 detour，"
        "活体探针立刻打脸：四个输入全返回同一个常数 1767657313（连 x=0 都不是 0），"
        "因为 rdx 其实是一个缩放标量（我传进去的指针低 32 位成了缩放值）。"
        "这条经验值得记：**函数体一样不等于 ABI 一样**，参数含义要看调用点。"
        "现在指向 0x1B4C0A0，签名 longlong* fn(longlong* ret /*rdx*/, longlong* src /*rcx*/)。",
    ),
    (
        "apply_mul_cfx",
        "CModifier::ApplyModifierMult(CFixedPoint&, CModifier const&, ModifierType, bool)",
        0x0036DF80,
        STRAT_EXACT,
        "**用「调用者」定位成功的**（函数体指纹分不出来，见 5.1）。"
        "方法：Linux 侧有 78 个函数调用 ApplyModifierMult，其中 35 个带字符串字面量；"
        "取 `CalcStarbaseCapacity`（它的 STARBASE_CAPACITY_MAX_REACHED 唯一命中 Windows "
        "dump 的 FUN_14073c540），发现它两次调用 `FUN_14036df80` —— 而后者体内正是"
        "`*(DAT_142814390 + 0xa0 + param_4*0xb0)` 的类型表查找 + `(v*m)/100000` + 拆分回退。"
        "与 Linux 962696 **逐行对应**："
        "`if (0x7ffffffe < (int)param_4) { *param_1 = 100000; return; }` 对应 "
        "`if (param_3 != 0x7fffffff)`；`*param_2 = (v*m)/100000`（**就地改写 CFixedPoint&**）"
        "对应 `*param_1 = lVar6`；`*param_1 = local_10; return param_1`（sret 返回**实际倍率**）"
        "对应 `return puVar4`。"
        "**为什么能做成 EXACT**：它返回实际生效的倍率，所以 detour 可以"
        "（1）先读入参 v0，（2）调原函数拿到真实倍率 m_eff，（3）用 cfx::mul 复算精确值并比对，"
        "完全**不需要**重新实现 CModifier 的类型表查找 —— 也就绕开了「逆清它内部结构」这个难题。"
        "ABI：sret — rcx=返回槽（倍率），rdx=CFixedPoint& 被就地改写，r8=CModifier const*，"
        "r9d=ModifierType，第 5 参数(bool)=栈上传。",
    ),
    (
        "apply_mul_fp15",
        "CModifier::ApplyModifierMult(fpml::fixed_point<...,15>&, CModifier const&, ModifierType, bool)",
        0x0036E0A0,
        STRAT_EXACT,
        "与 apply_mul_cfx 地址相邻（0x36E0A0 vs 0x36DF80），是同一族的第二个重载。"
        "体内把 `operator fpml::fixed_point<...,15>` **内联**了（所以按「调用 FUN_141b4c0a0」"
        "搜不到，我一开始就是这么搜空的）："
        "`*param_2 = (((local_10 % 100000) * 0x40000000) / 0xc3500000 + (local_10 / 100000) * 0x8000)"
        " * *param_2 >> 0xf;` —— 与 Linux 962872 的"
        "`CFixedPoint::operator_cast_to_fixed_point(...); *param_1 = local_18 * *param_1 >> 0xf;` 一致。"
        "同样**返回实际倍率**（`*param_1 = local_10`），所以也能做成 EXACT。"
        "ABI：同 apply_mul_cfx，只是第 5 个 bool 参数在这里恒为 0（内联调用）。",
    ),
    (
        "cfx_round_to",
        "CFixedPoint::RoundTo(CFixedPoint const&)",
        0x01B4C1B0,
        STRAT_OBSERVE,
        "win dump FUN_141b4c1b0（31 行）与 Linux CFixedPoint::RoundTo（反编译 8599448）同构："
        "先按 `lVar3 + 0x53e2d6238da3U < 0xa7c5ac471b47` 判量级（0x53e2d6238da3 = 2^62/5 量级的安全界），"
        "小量级走 `(lVar3*100000)/200000`、大量级走 `(lVar2%200000)*100000/200000 + (lVar3%100000)*100000/200000` "
        "的拆分路径，最后 `*param_1 = lVar3 - lVar3 % lVar2; return lVar3 / lVar2;` —— "
        "结尾这三行与 Linux 版的 `*(ulong *)this = uVar3 - (long)uVar3 % (long)uVar4; "
        "return (long)uVar3 / (long)uVar4;` 逐字对应。"
        "**ABI**：非 sret，返回值在 rax；rcx = this（会被就地改写），rdx = 除数(CFixedPoint const&)。"
        "**为什么是 OBSERVE**：Linux 侧同样只观测（记录 divisor==0 与 v+divisor/2 溢出），"
        "没有写精确饱和参考实现 —— 它的拆分路径要逐位等价重写成本高，先看实机有没有 divisor==0。",
    ),
    (
        "cfx_atan2",
        "CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&)",
        0x01B4C2D0,
        STRAT_OBSERVE,
        "win dump FUN_141b4c2d0（98 行，Linux Atan2 也是这个量级）同时命中 **Atan2 的五个标志常量**："
        "`0x132cb`(= 3.1416/4 × 1e5，Linux 版 `(long)(uVar8 * 0x132cb) / 100000` 用的就是这个)、"
        "`0x39863`(= 3.1416 × 1e5，Linux 版的 `lVar5 = 0x39863`)、"
        "`0x53e2d6238da3`、以及安全域常量 `0xb504f333`/`0x16a09e667`。"
        "五个常量同时出现，是这一族里最强的一次指纹命中。"
        "**ABI**：sret(param_1=rcx 返回槽, param_2=rdx 第一个 CFixedPoint, param_3=r8 第二个)。"
        "**为什么是 OBSERVE**：Linux 侧同样只观测（记录参数平方会溢出的量级），"
        "原因写在 Linux README 第 5 节：Atan2 是多项式逼近，重写逐位等价参考实现成本高且容易错。",
    ),
    (
        "var_multiply",
        "CMultiplyVariableEffect::ExecuteActual(CEventScope&) const",
        0x01777F00,
        STRAT_OBSERVE,
        "**RVA 已更正 —— 旧的 0x00231640 装错了函数，见下。**"
        "确证方式（字符串 + 调用者语义）：Linux 版 CMultiplyVariableEffect::ExecuteActual "
        "（反编译 6574198-6574255）里有一条独占的诊断串 "
        "`multiply_variable: variable %s is not set for scoped %s '%s' at %s`。"
        "在 Windows dump 里按该串检索，**唯一命中 FUN_141777f00**。"
        "体形也逐条对上：先 FUN_1409f7df0(scope, this+0xc0) 取变量（= Linux 的 "
        "AccessVariablePointer）、变量未设时走上面那条串、否则 FUN_14034d500(this+0xf0,…) 取 "
        "CFixedPointVariableValue::GetValue（= Linux 的 (this+0xe8)，MSVC 把值成员排到 0xf0）、"
        "FUN_140227390 取当前值（= CVariables::GetVariable）、"
        "FUN_1407aae10(…, v*d/1e5) 写回（= CVariables::SetVariable）。"
        "四个 helper 的对应关系是从 Linux 的调用序一一对出来的，不是猜的。"
        "**旧 RVA 为什么错**：0x00231640 体内有 `type*0xb0 + 0x9c + DAT_142814390` 的 "
        "CModifier 类型表掩码查表，并就地累加 `*(param_1+0x38)` 的 0x10 步长数组 —— "
        "那是 CModifier 惯用法，**不是变量系统**；它既没有那条诊断串，也没有上面四个 helper。"
        "（真正的 CModifier 放大出口是 apply_mul_cfx=0x36DF80，那条路已经单独确证。）"
        "ABI：void fn(this /*rcx*/, CEventScope* /*rdx*/)。",
    ),
    (
        "var_add",
        "CAddVariableEffect::ExecuteActual(CEventScope&) const",
        0x01777800,
        STRAT_OBSERVE,
        "确证方式（调用者法 + 体形比对）：先用**已确证的** var_multiply（0x1777F00）"
        "提取出它调用的 4 个 helper RVA（0x9F7DF0 / 0x34D500 / 0x227390 / 0x7AAE10），"
        "再在 dump 里找「同时调用这 4 个」的函数 —— 命中 6 个（正是变量效果家族），"
        "其中**不含乘法安全域常量 0xb504f333 的 26 行成员有两个**：0x1777800 与 0x1777C80。"
        "读体区分：0x1777800 写回 `local_res18[0] + lVar2`（= 值 + 当前变量，加法），"
        "0x1777C80 写回 `lVar2 - local_res18[0]`（= 当前变量 - 值，减法）。"
        "对照 Linux：CAddVariableEffect::ExecuteActual（6573500）写回 `puVar2 + lVar3` "
        "（= GetValue 的返回值 + GetVariable 的返回值，**纯加法、无符号处理**），"
        "而 CSubtractVariableEffect 走的是另一套（带减法语义）。"
        "所以 0x1777800 = CAddVariableEffect。"
        "**为什么是 OBSERVE 而不是 EXACT**：Linux 侧虽然列 EXACT，但它的 EXACT 依赖"
        "**先读到 v0**（hook 前 GetVariable）再复算饱和加法；Windows 上 v0 的读取路径是 "
        "FUN_140227390 + 名字 CString 布局，尚未验证，贸然 EXACT 会写坏存档。"
        "先用 OBSERVE 计数、看实机量级，确认 helper 语义后再升级。"
        "ABI：void fn(this /*rcx*/, CEventScope* /*rdx*/)。",
    ),
    (
        "cfx_get_rounded_fp15",
        "CFixedPoint::GetRounded(fpml::fixed_point<long long,48,15> const&)",
        0x01B4C100,
        STRAT_OBSERVE,
        "win dump FUN_141b4c100（23 行）与 Linux CFixedPoint::GetRounded(fpml::fixed_point<...> "
        "const&)（反编译 8599289）结构同构："
        "uVar3 = x<1 ? (-(uint)((x & 0x7fff)!=0) & 0x8000) + x : x; "
        "lVar4 = (int)(uVar3 >> 0xf); lVar2 = ((x + lVar4*-0x8000) * 0xc3500000) >> 0xf; "
        "*ret = (int)(((lVar2 - (ulonglong)(lVar2<1)) + 0x4000) >> 0xf) + lVar4*100000;"
        "四个特征常量（0x8000、0xf、0xc3500000、0x4000）与 Linux 版逐一对上。"
        "**为什么是 OBSERVE**：它中间有 (…)*0xc3500000 的 64 位乘，可能与游戏其它定点运算一样"
        "在极大输入下 wrap；但 Linux 侧也没为它写精确饱和参考实现（同列为 OBSERVE），"
        "所以这里只计数、不判罚，先看实机有没有异常量级。"
        "意外收获：它紧邻已确证的 GetRounded（0x1B4C170），说明 CFixedPoint 的成员在 "
        "0x1B4C0A0..0x1B4CE80 成簇排布 —— 这是继续定位其余 CFixedPoint 成员的捷径。",
    ),
    (
        "shield_max",
        "NShipUtil::CalcMaxShieldHitPoints(CBaseDesignImplementation const&, CModifier const&, "
        "CFleet const*, CToolTip*)",
        0x00A11D80,
        STRAT_OBSERVE,
        "**按「CShipSize 修正类型表偏移」确证，两条独立签名同时命中。**"
        "签名一（表偏移）：Linux 版体内有 6 个该表的索引常量 "
        "0x1614c/0x16158/0x161fc/0x16208/0x162ac/0x162b8（= ModifierType 枚举值，"
        "护盾专用的 7 个修正），逐个在 110843 个函数块里检索，**全部只出现在 FUN_140a11d80**。"
        "签名二（结构偏移）：体内从 param_2 读 `+0x130`，与 Linux 反编译 "
        "（1335625-1336177，`*(param_9 + 0x130)`）一致。"
        "签名三（邻居）：Linux 里 CalcMaxHitPoints/CalcMaxShieldHitPoints/CalcMaxArmorHitPoints "
        "连续排布，Windows 里 FUN_140a112a0/FUN_140a11d80/FUN_140a12910 也连续，"
        "且 armor 已由 0x15fec/0x15ff8/0x160a8 独立确证为第三位 —— 位置关系吻合。"
        "ABI：sret（体内 `*param_1 = ...` 6 处、`return param_1`），与 Atan2 同形。"
        "**为什么是 OBSERVE**：Linux 侧同列 OBSERVE（护盾上限 = 船体尺寸基础值 × 一连串乘法修正，"
        "其中大量乘法被内联，现有 ApplyModifierMult 钩子抓不到）。判据：正常护盾上限必 ≥ 0 且 "
        "不会离谱；负数或量级异常 = 几乎必然是 wrap。",
    ),
    (
        "armor_max",
        "NShipUtil::CalcMaxArmorHitPoints(CBaseDesignImplementation const&, CModifier const&, "
        "CFleet const*, CToolTip*)",
        0x00A12910,
        STRAT_OBSERVE,
        "**本目标的确证强度最高：常量三元组在 110843 个函数块里唯一。**"
        "Linux 版体内有装甲专用的表索引常量 0x15fec/0x15ff8/0x160a8；"
        "把这三个常量同时作为检索条件扫过全部函数块，**命中数 = 1**，就是 FUN_140a12910。"
        "（对比：同族的 hull 用 0x13b7c/0x13b88/0x13c38/0x15398/0x15448，shield 用 "
        "0x1614c/0x16158/0x16208/0x162b8 —— 三者的常量集互不相交，所以这个判据不会串台。）"
        "签名二：体内从 param_2 读 `+0x70`，与 Linux 反编译 1336255 的 "
        "`*(undefined1 **)(param_9 + 0x70)` 逐字对上。"
        "ABI：sret（`*param_1 = ...` 6 处、`return param_1`）。"
        "**为什么是 OBSERVE**：与 shield 同理，Linux 侧也列为观测点。",
    ),
    (
        "hull_max",
        "NShipUtil::CalcMaxHitPoints(CBaseDesignImplementation const&, CModifier const&, "
        "CFleet const*, CToolTip*)",
        0x00A112A0,
        STRAT_OBSERVE,
        "**按「CShipSize 修正类型表偏移」确证。**签名一（表偏移）：Linux 版体内有船体专用的 "
        "索引常量 0x13b7c/0x13b88/0x13c2c/0x13c38/0x1538c/0x15398/0x1543c/0x15448，"
        "逐个检索后 0x13b7c/0x13b88/0x13c38/0x15398/0x15448 **只出现在 FUN_140a112a0**"
        "（0x13c2c/0x1538c/0x1543c 在本函数里以其它形式被折叠掉了）。"
        "签名二（结构偏移）：体内从 param_2 读 `+0x10`，与 Linux 反编译 "
        "（1335070-1335619，`*(param_9 + 0x10)`）一致。"
        "签名三（邻居）：它是这三个连续函数里的**第一个**，与 Linux 的排布顺序一致"
        "（Linux 1335620 CalcMaxHitPoints → 1336178 CalcMaxShieldHitPoints → 1336667 "
        "CalcMaxArmorHitPoints；Windows 0xA112A0 → 0xA11D80 → 0xA12910）。"
        "ABI：sret（`*param_1 = ...` 6 处、`return param_1`）。"
        "**为什么是 OBSERVE**：与 shield 同理，Linux 侧也列为观测点。",
    ),
    (
        "cfx_sqrt",
        "CFixedPoint::Sqrt() const  /  fixed_int64::sqrt(fixed_int64*)",
        0x01B489D0,
        STRAT_INPUT_GUARD,
        "**用「调用者法」定出来的（与 apply_mul_cfx 同一套路，本轮第二次奏效）。**"
        "先找 Linux 里谁调用 Sqrt：只有 CalcDistance(1987515)、"
        "SetCardinalPatronAttunement、HackyButSafeSqrt、CalculateTargetRotationAndSpeed 四个。"
        "其中 CalcDistance 体内同时调用 Sqrt 与 SafeSqrt，且带一个独特常量 0xf4241(=1000001)；"
        "按该常量在 Windows 侧检索得到 3 个候选，其中 FUN_140997d30 含 CFixedPoint 专属魔数 "
        "0x29f16b11c6d1e109 与平方安全界 0xb504f333 —— 读体确认它是 CalcDistance 同构体，"
        "而它调用的 FUN_141b489d0 正是 Sqrt。"
        "**体形确证**（与 Linux 8599313 逐步同构）："
        "`lVar1=*src; if (1 < lVar1) { lVar3 = lVar1/2;`（初始猜测 = x/2）"
        "`lVar7 = (lVar1*1000)/100000;`（收敛容差 = sqrt 的 1/100 近似）"
        "`do { lVar5 = lVar3*lVar3/100000 - lVar1;`（牛顿残差）"
        "`lVar4 = lVar5*100000/(2*lVar3); lVar6 = lVar3 - lVar4; }`（牛顿更新）"
        "`while ((lVar7 < lVar5 || lVar5 < -lVar7) && lVar4 != 0 && lVar6 != lVar3);`"
        "—— 循环条件与 Linux 的 `(uVar5 < -uVar8 || uVar8 < uVar5) && uVar2 != 0` 逐项对应。"
        "ABI：sret（`*param_1 = lVar6; return param_1`）。"
        "**注意**：Linux 版返回 ulong（RAX），Windows 版走 sret 写回 —— 同一算法的两种 ABI 表达，"
        "所以这里按 Windows 的实际机器码定签名，不照抄 Linux。"
        "策略 INPUT_GUARD：Linux 侧的判据是「负输入会被当巨大无符号数迭代，结果无意义」，"
        "所以只在 x<0 时记一行。",
    ),
    (
        "cfx_safe_sqrt",
        "CFixedPoint::SafeSqrt() const",
        0x01B4C600,
        STRAT_OBSERVE,
        "**从上一步的结果顺出来的**：确证 Sqrt(0x1B489D0) 后找它的调用者，"
        "发现 FUN_141b4c600 既是「Sqrt 的调用者」又是「被 7 个函数调用的公用入口」。"
        "读体与 Linux CFixedPoint::SafeSqrt() const（8599678）**逐行同构**："
        "`if (x < 0x2711)`（=10001，安全域下界）→ `x *= 100`（乘 100 进域）"
        "→ `Sqrt(&x)` → `if (r + 0xb504f333 < 0x16a09e667) r = r*10000/100000;`"
        "（= r/10）`else` 走 `((r % 100000) * 10000)/100000 + (r/100000)*10000` 的拆分路径；"
        "否则（x >= 0x2711）先循环 `while (2999999999 < x) { x = x*1000/100000; n++; }`"
        "把 x 缩进域、记下缩放次数 n，算完再 `do { r *= 10; } while (n--)` 补回来。"
        "常量 0x2711 / 10000 / 1000 / 2999999999 与 Linux 版**逐个对上**。"
        "**为什么是 OBSERVE**：Linux 侧同列 OBSERVE，判据是「x<0 时原实现结果无意义」。"
        "ABI：sret（`longlong* fn(longlong* ret /*rcx*/, const longlong* src /*rdx*/)`）。",
    ),
    (
        "diplo_weight",
        "CPopJob::CalcDiplomaticWeight(CPopGroup const&) const",
        0x00838670,
        STRAT_OBSERVE,
        "**本轮最有价值的一个 —— 用「NDefines 名字 thunk」定出来的全新方法。**"
        "难点背景：这个函数在 Linux 里**没有任何直接调用者**（只有 4 处提及，全是它自己），"
        "所以「调用者法」对它无效；而按守卫密度筛出 24 个候选、按结构偏移 `+0x808` 命中 0 个。"
        "**突破口**：Paradox 的 NDefines 名字字符串（如 `DIPLOMACY_WEIGHT_POP_BASE`）"
        "确实存在于 exe 的 .rdata（VA 0x142360e08）。"
        "扫 .text 找 rip-relative 引用它的指令，**各只有 1 处**，落在 0x382580 / 0x3825a0。"
        "反汇编那两处是一个 5 指令 thunk："
        "`mov rcx,rdx; lea r9,[全局]; lea rdx,[\"NGameplay\"]; lea r8,[\"<名字>\"]; "
        "jmp <注册函数>` —— 于是**名字 -> 全局地址**的对应关系被直接读出来："
        "`DIPLOMACY_WEIGHT_POP_BASE -> 0x143151010`、"
        "`DIPLOMACY_WEIGHT_POP_HAPPINESS -> 0x143151008`。"
        "再在全部 110843 个函数块里找「同时读这两个全局」的函数 —— **命中数 = 1**，就是本函数。"
        "**体形逐条对上 Linux（1177404-1177484）**："
        "`param_3+8` 虚调用（Linux `param_10+8` 的 vtable slot）、"
        "`param_1+0x18` 取 CJobType（同偏移）、"
        "`param_1+0xec` 计数 / `param_1+0xe0` 数组（**两个偏移与 Linux 完全相同**）、"
        "`(arr)[i*2+1] * 100000`、"
        "`(lVar4 * DAT_143151010)/100000`（= 乘 POP_BASE）、"
        "`FUN_14067eec0(param_3)`（= CPopGroup::HasHappiness）、"
        "`(uVar5 * DAT_143151008)/100000`（= 乘 POP_HAPPINESS）、"
        "`*(param_3+0x8b0)` 再相乘、最后 `uVar5 + lVar4` 求和并写回 sret。"
        "**顺带解答了上轮的疑问**：Linux 读 `param_10+0x808`，Windows 读 `param_3+0x8b0` —— "
        "这就是为什么按 `+0x808` 检索命中 0 个。MSVC 布局差异又一次得到实证。"
        "ABI：sret（`*param_2 = uVar5; return param_2`），"
        "签名 `longlong* fn(const void* self /*rcx*/, longlong* ret /*rdx*/, const void* group /*r8*/)`。"
        "策略 OBSERVE：与 Linux 同 —— 外交权重是各项加权和，**不可能为负**；"
        "返回负数或量级离谱就是 wrap 的证据，不需要复算。",
    ),
    (
        "mpe15",
        "NCombatRules::CalcMilitaryPowerExponent(fpml::fixed_point<long long,48,15>, "
        "fpml::fixed_point<long long,48,15>)",
        0x00A0A4A0,
        STRAT_OBSERVE,
        "**靠「NDefines 名字法」顺出来的（第三个方法，本轮第二次用它破局）。**"
        "上两轮对这个目标完全卡住：调用者法无效（调用者不带独占字符串）、"
        "常量法无效（Linux 的 0x15bf1 与 0x7fffffff8000 在 Windows 侧都是 0 次）、"
        "递归判据无效（73 个自递归函数里没有一个是它）。"
        "本轮先用 NDefines 名字法建出 **2369 个** (名字, 组, 全局地址) 三元组"
        "（解析器用已确证的 DIPLOMACY_WEIGHT_POP_BASE/HAPPINESS 做校准，"
        "两者地址与前面独立确证的结果**完全一致**，证明解析器可信），"
        "于是拿到 `MILITARY_POWER_EXPONENT -> 0x1431505B0`（组 = NShip）。"
        "顺着它找到唯一读它的函数 FUN_140a08960，它把这个 define 当**指数**"
        "传给 `FUN_140a0a610` —— 那就是幂函数。"
        "`FUN_140a0a610` 的移位是 `<<7` / `>>7` / `0x80` / `0x7f`，是 **fp7** 编码，"
        "所以它是 mpe7；而它紧邻的 `FUN_140a0a4a0`（同样的体形、同样调用一个 log2 辅助）"
        "移位是 `<<0xf` / `>>0xf` / `0x8000` / `0x7fff`，是 **fp15**，即本目标。"
        "**编码判定与 Linux 完全吻合**：Linux mpe15 体内的掩码常量是 "
        "0x7fffffff8000 / 0xffffffffffff8000（fp15 的 0x7fff/0x8000），"
        "Linux mpe7 的是 0x7fffffff80 / 0xffffffffffffff80（fp7 的 0x7f/0x80）。"
        "体形也一致：都是「处理负指数 -> 调 log2 辅助 -> 累加收敛循环」，"
        "收敛条件都是 `while (sum != next + sum)`（加下一项不再改变和即停）。"
        "ABI：sret —— `longlong* fn(longlong* out /*rcx*/, const longlong* base /*rdx*/, "
        "const longlong* exp /*r8*/)`。"
        "**注意参数顺序**：Linux 版是 (out, 指数, 底数)，Windows 是 (out, 底数, 指数) —— "
        "两者相反。这是本轮第 4 次「同族函数 ABI 顺序不一致」的实例。"
        "策略 OBSERVE：Linux 侧同 —— 只记录「中间积会撑爆 int64」的调用，不改数值"
        "（pow 的等价饱和实现风险高）。",
    ),
    (
        "mpe7",
        "NCombatRules::CalcMilitaryPowerExponent(fpml::fixed_point<long long,56,7>, "
        "fpml::fixed_point<long long,56,7>)",
        0x00A0A610,
        STRAT_OBSERVE,
        "与 mpe15 同源、同一轮确证（见上条）。判据是**编码**："
        "本函数用 `<<7` / `>>7` / `0x80` / `0x7f` / `0xffffffffffffff80`，"
        "是 fpml 的 7 位小数编码；而 Linux mpe7 体内的掩码常量正是 "
        "0x7fffffff80 / 0xffffffffffffff80 / 0xffffffffffffff00 —— 逐个对上。"
        "**额外证据**：唯一读 `MILITARY_POWER_EXPONENT` 的函数 FUN_140a08960 "
        "就是调用本函数（不是 0xA0A4A0），且它整条路径都用 `>> 7` / `>> 8` 的移位 —— "
        "说明军力权重那条代码路径确实走 fp7 编码。"
        "它还有一个专用的 log2 辅助 FUN_140a0a840（fp7 版），"
        "与 mpe15 用的 FUN_140a0a770（fp15 版）成对。"
        "ABI 与 mpe15 相同：`longlong* fn(longlong* out, const longlong* base, "
        "const longlong* exp)`。策略 OBSERVE，同 Linux。",
    ),
    (
        "damage_per_day",
        "NShipUtil::CalcAverageDamagePerDay(CBaseDesignImplementation const&, ...) "
        "—— 设计师面板的「伤害」",
        0x003C2910,
        "OBSERVE",
        "**对照 Linux 符号名定出来的（用户建议「对照 linux 版本的代码库」，一次命中）。**"
        "Linux 侧这个函数叫 `NShipUtil::CalcAverageDamagePerDay`（868 行），"
        "体内有一个**独占的安全界常量 `0xb50679d3`**（不是常见的 0xb504f333）—— "
        "它出现在末尾那次「乘以 (add+1.0)」的快速路径判定里："
        "`if (x + 0xb50679d3 < 0x16a09e667) ...`。"
        "在 Windows dump 里搜该常量只得到 3 个候选，其中 FUN_1403c2910 是 851 行"
        "（Linux 868 行，量级吻合），且体内**恰好也只有 1 处** 0xb50679d3（末尾）。"
        "**逐条对上 Linux**："
        "末尾算式 Linux `local_b8 = (local_b8 * (local_60+100000)) / 100000`"
        "对应 Windows `lVar9 = (lVar9 * lVar22) / 100000`（L700，同一位置）；"
        "拆分回退分支 `(X%1e5)*Y/1e5 + (X/1e5)*Y` 两边逐字一致；"
        "GetModifierValue 的调用点两边都用 `CShipSize::GetModifierValue`，"
        "且 Windows 侧传的 type 0x41/0x168/0x230 与 Linux 的 0x41/0x168/0x230 **同号**。"
        "**溢出点**：L699-710 那次乘法是**裸 64 位乘**，没有饱和 —— 伤害被 mod 堆大后在这里 wrap。"
        "**为什么是 OBSERVE**：它的 ABI 与 Linux 不同 —— Linux 版 `return local_b8`（值在 rax），"
        "Windows 版是 `void fn(obj, int idx, longlong* out, param_4)`（唯一调用者 "
        "FUN_140c9e3f0 的 L142-143 确证），结果写进 out 结构的 `+0x98`。"
        "要回写就得先逆清那个 out 结构的语义，风险高于收益，所以先观测。"
        "判据：伤害不可能为负，出现负数或量级离谱（> 9.2e13 游戏单位）就是 wrap。",
    ),
]

# ---------------------------------------------------------------------------
# 尚未确证的目标（Linux 版里有，Windows 侧还没定位）
#
# 明确列出来而不是假装支持：插件会在启动日志里报告"未定位 N 个"，
# 后续用同样流程（win_fingerprint.py 出候选 -> 读函数体确证）逐个补。
# ---------------------------------------------------------------------------
UNRESOLVED: list[tuple[str, str, str]] = [
    ("cfx_safe_sqrt_int", "CFixedPoint::SafeSqrt(long long)  —— **已判定：Windows 侧无对应代码，非缺口**",
     "**结论（有证据，不是推测）**：MSVC 不生成这个重载，所以 Linux 那条 INPUT_GUARD 在 Windows 上没有可挂的对象。"
     "定位过程：Linux 侧 SafeSqrt(long long) 的**唯一**真实调用点是 MTTHModifyNumber 的 case 0xf（脚本 sqrt 运算符），"
     "该分支前面有一句独占报错串 `script_value/MTTH/weight field: Cannot square root a number that is negative at %s`。"
     "按该串在 Windows dump 里检索 -> **唯一命中 FUN_14033fd20**（= Windows 的 MTTHModifyNumber，176 行 switch）。"
     "读它的 case 0xf："
     "`if (-1 < (longlong)*param_1) { puVar4 = FUN_141b4c600(param_1,&local_20); *param_1 = *puVar4; return 1; }` "
     "—— 它**直接把 param_1（一个 CFixedPoint*）的地址**传给 SafeSqrt(CFixedPoint const&)，"
     "**没有 `p * 100000` 这一步**。"
     "原因：case 0xf 里 param_1 本来就是定点格式的 CFixedPoint*，值已经在格式内，"
     "所以编译器直接用引用重载，不需要「整数 -> 定点」的换算 —— 那个 p*100000 压根不生成。"
     "**对照表**：Linux `SafeSqrt(param_9)` 实参是整数 long（所以重载里有 p*100000 溢出点）；"
     "Windows `FUN_141b4c600(param_1, ...)` 实参是指针（无该步）。"
     "**另外**：case 0xf 自己已有负值检查（负 -> 报错返回，不计算），"
     "所以 Linux 那个 INPUT_GUARD 要防的场景，游戏在本路径上已自行防护。"
     "**而真正的 sqrt 求值路径已被覆盖**：FUN_141b4c600 就是已装的 cfx_safe_sqrt 钩子（含 x<0 判定）。"
     "附：我试过的其他定位手段都失败，一并留档 ——"
     "(a) 精确签名搜「0x2710 + 0xb504f333 + 0x16a09e666 三件套」全库仅 1 处（真函数本身），无内联副本；"
     "(b) 按 SafeSqrt 的 6 个调用点逐个反汇编，无一是 p*100000 形态；"
     "(c) 用 80 字节窗口搜出的 3 个「疑似内联点」经读体确认是 x*x 乘法辅助函数（假阳性）。"),
]

# ---------------------------------------------------------------------------
# 辅助函数：只解析地址（同样做序言签名校验），不装钩子
#
# 这四个是变量系统 EXACT 的前提：要能在**调用原函数之前**读回变量当前值，
# 才能复算饱和结果并与游戏写回值比对。
# ---------------------------------------------------------------------------
HELPERS: list[tuple[str, str, int, str]] = [
    (
        "access_var_pointer",
        "AccessVariablePointer(CEventScope&, CString const&)",
        0x009F7DF0,
        "从 var_multiply 的调用点读出。体内先建字符串 \"local_\" 再 "
        "FUN_141b2f670(name, len, 0, \"local_\", 6)（= 拼前缀判断），"
        "随后按 CEventScope 是否已绑定分别走 FUN_1403965c0/FUN_140396a90/FUN_140392020 —— "
        "与 Linux AccessVariablePointer 的三分支同构。ABI：longlong fn(scope, name)。",
    ),
    (
        "cvars_get",
        "CVariables::GetVariable(CString const&) const",
        0x00227390,
        "从 var_multiply 的调用点读出（实参是 vars+8，所以它接的是 CVariables 的哈希表头）。"
        "体内 FUN_141b430e0(0, name, len) 算哈希，`(uVar3 & uVar5)*0x40 + *(param_1+8)` 定位桶，"
        "再 memcmp 比名字；**返回条目指针**，条目 +0x38 就是 CFixedPoint 值。"
        "调用方读 `*(longlong *)(entry + 0x38)` —— 这一条直接给出了变量值的存放偏移。"
        "ABI：longlong* fn(vars, out_slot, name)，返回 out_slot。",
    ),
    (
        "cvars_set",
        "CVariables::SetVariable(CString const&, CFixedPoint)",
        0x007AAE10,
        "从 var_multiply 的调用点读出。体内 FUN_1407ab940(vars+8, &entry, hash, name, &value)，"
        "当 `local_10 == '\\0'`（条目已存在）时写 `*(entry + 0x38) = value` —— "
        "与 cvars_get 的读偏移 0x38 **互为印证**。ABI：void fn(vars, name, value)。",
    ),
    (
        "cfp_getvalue",
        "CFixedPointVariableValue::GetValue(CEventScope&) const",
        0x0034D500,
        "从 var_multiply 的调用点读出（实参是 this+0xf0，MSVC 把该值成员排在 0xf0；"
        "Linux 是 0xe8）。体内按变量值类型分派后把 CFixedPoint 写进 out 槽。"
        "ABI：longlong* fn(this+0xf0, out_slot, scope)，返回 out_slot。",
    ),
    (
        "ship_size_of",
        "CShipSize* —— 从 CBaseDesignImplementation 取当前成长阶段的船体尺寸",
        0x0030E990,
        "**护盾/装甲/船体上限做忠实重算的前提。**三个上限函数体内都是 "
        "`lVar9 = FUN_14030e990(param_2)` 然后把这个返回值当 CShipSize 传给 "
        "GetModifierValue —— 所以它就是 Linux 的 "
        "`stage = GetCurrentGrowthStage(design); size = *(stage + 8)` 两步的合并体："
        "体内 `lVar2 = (**(code**)(*param_1 + 0x10))()` 虚调用拿阶段对象，"
        "再按 `*(param_1 + 0x52c)` 这个成长阶段下标从 `*(lVar2 + 0x20)` 的 0x110 步长数组里取"
        "（越界则回落到第 0 个），取出的 `+8` 字段就是 CShipSize。"
        "注意它同时覆盖了 Linux 的 GetCurrentGrowthStage + 解引用，**不需要**再单独定位后者。"
        "ABI：void* fn(const void* design) —— 单参数，返回值在 rax。",
    ),
    (
        "modifier_value",
        "CShipSize::GetModifierValue(CModifier const&, ModifierType) const",
        0x00D29DD0,
        "**重算链的取值原语。**三个上限函数体内反复出现 "
        "`FUN_140d29dd0(size, &out, mods, type)`，type 就是 ModifierType "
        "（hull 0x1e/0x1f、shield 0x2e/0x2f、armor 0x24/0x25）。"
        "体内：按 `*(mods + 0x1c)` 的条目数线性扫 `*(mods + 0x10)` 的 type 数组，"
        "命中后取 `*(mods + 0x38) + i*0x10` 的值；"
        "若该 type 的位掩码 `(*(DAT_142814390 + type*0xb0 + 0xa8) >> 5 & 1)` 置位，"
        "则把结果夹进 [0, 100000]（负数→0，>1.0→1.0）；"
        "随后再对 `FUN_140d2c080(size, type)` 查一次「该尺寸的同类修正」并**相加**，"
        "写进 `*param_2` 返回。"
        "**与 Linux 的差异**：Linux 版是 3 参数返回值在 rax，Windows 是 4 参数 sret "
        "（第 2 参数是 out 槽）—— 按 Windows 机器码定签名，不照抄 Linux。"
        "ABI：longlong* fn(const void* size /*rcx*/, longlong* out /*rdx*/, "
        "const void* mods /*r8*/, int type /*r9d*/)，返回 out。",
    ),
]

HEADER_TEMPLATE = """\
// ===========================================================================
//  自动生成，不要手改 —— 由 tools/gen_targets_win.py 产出
//
//  来源二进制 : {exe}
//  文件大小   : {size} 字节
//  PE TimeDateStamp : 0x{ts:08X}
//  ImageBase  : 0x{ib:x}
//  生成时间   : {when}
//  确证目标   : {found}/{total}（另有 {unresolved} 个尚未定位）
//
//  与 Linux 侧的根本差别
//  ---------------------
//  Windows 的 stellaris.exe 没有 PDB、只导出 110 个符号、没有任何 C++ 符号，
//  所以**不能**像 Linux 那样按 mangled 名 dlsym。这里换成：
//
//      RVA（静态分析确证） + 序言字节签名（运行时校验）
//
//  运行时先比对签名，不匹配就停用该目标并写日志 —— 不盲目读写内存。
//  每个目标的形状证据见 tools/gen_targets_win.py 里的 CONFIRMED 表。
// ===========================================================================
#ifndef SATFIX_WIN_TARGETS_GENERATED_HPP
#define SATFIX_WIN_TARGETS_GENERATED_HPP

#include <cstdint>

#define SATFIX_WIN_EXE_TIMESTAMP 0x{ts:08X}u
#define SATFIX_WIN_IMAGE_BASE    0x{ib:x}ull
#define SATFIX_WIN_SIG_LEN       {siglen}
#define SATFIX_WIN_FOUND         "{found}/{total}"
#define SATFIX_WIN_UNRESOLVED    {unresolved}

namespace satfix_win {{

enum Strategy : uint8_t {{
  kExact      = 0,   ///< 有精确饱和参考实现，可逐位比对、可替换
  kInputGuard = 1,   ///< 危险在输入域：先把输入夹到安全域再调原函数
  kObserve    = 2,   ///< 只判定"是否进入危险域"，只记日志
  kDisabled   = 3,   ///< 地址已确证但 ABI 未确认 -> 拒绝安装（安全失败）
}};

struct Target {{
  const char*     key;
  const char*     desc;
  uint32_t        rva;        ///< 相对 ImageBase
  const uint8_t*  sig;        ///< 序言签名（SATFIX_WIN_SIG_LEN 字节）
  uint8_t         strategy;
  const char*     evidence;   ///< 形状证据（怎么确证的）
}};

/// 只解析地址、不装钩子的辅助函数。
struct Helper {{
  const char*     key;
  const char*     desc;
  uint32_t        rva;
  const uint8_t*  sig;
  const char*     evidence;
}};

{arrays}

inline const Target kTargets[] = {{
{rows}
}};

inline constexpr int kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

/// 尚未定位的目标 —— **只放一行短摘要**，给启动日志用。
///
/// 为什么不放完整证据：这些证据动辄几百字（含反编译片段、证伪过程），
/// 早先直接塞进这里，结果启动日志被刷成 4000 行上限，把真正有用的
/// 「hooked …」行挤掉了。完整证据在 tools/gen_targets_win.py 的
/// UNRESOLVED 里，要看证据去那里看；辅助函数的证据在 HELPERS 里。
inline const char* const kUnresolved[] = {{
{unresolved_rows}
}};

inline constexpr int kUnresolvedCount = sizeof(kUnresolved) / sizeof(kUnresolved[0]);

/// 辅助函数：只解析地址，不装钩子。
///
/// 用途：var_add / var_multiply 要做 EXACT，必须能**读回变量的当前值**再复算饱和加法/乘法。
/// 这四个就是那条路径。它们同样带序言签名，游戏更新后会被校验挡下。
inline const Helper kHelpers[] = {{
{helper_rows}
}};

inline constexpr int kHelperCount = sizeof(kHelpers) / sizeof(kHelpers[0]);

}}  // namespace satfix_win

#endif  // SATFIX_WIN_TARGETS_GENERATED_HPP
"""


def read_sig(pe: "pefile.PE", rva: int, n: int = SIG_LEN) -> list[int]:
    off = pe.get_offset_from_rva(rva)
    return list(pe.__data__[off:off + n])


def c_bytes(bs: list[int]) -> str:
    return ", ".join(f"0x{b:02x}" for b in bs)


def c_str(s: str) -> str:
    out = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return '"' + out + '"'


def build(exe: Path) -> str:
    pe = pefile.PE(str(exe), fast_load=True)
    ts = pe.FILE_HEADER.TimeDateStamp
    ib = pe.OPTIONAL_HEADER.ImageBase

    arrays = []
    rows = []
    for key, desc, rva, strat, ev in CONFIRMED:
        sig = read_sig(pe, rva)
        arrays.append(f"inline const uint8_t kSig_{key}[SATFIX_WIN_SIG_LEN] = "
                      f"{{ {c_bytes(sig)} }};")
        rows.append(
            f"    {{{c_str(key)}, {c_str(desc)}, 0x{rva:08x}u, kSig_{key}, "
            f"{STRAT_ENUM[strat]}, {c_str(ev)}}},"
        )

    unresolved_rows = [f"    {c_str(f'{t[0]}  —  {t[1]}')}," for t in UNRESOLVED]

    helper_rows = []
    for key, desc, rva, ev in HELPERS:
        sig = read_sig(pe, rva)
        arrays.append(f"inline const uint8_t kSig_{key}[SATFIX_WIN_SIG_LEN] = "
                      f"{{ {c_bytes(sig)} }};")
        helper_rows.append(
            f"    {{{c_str(key)}, {c_str(desc)}, 0x{rva:08x}u, kSig_{key}, {c_str(ev)}}},")

    import datetime
    return HEADER_TEMPLATE.format(
        exe=str(exe),
        size=exe.stat().st_size,
        ts=ts,
        ib=ib,
        when=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        siglen=SIG_LEN,
        found=len(CONFIRMED),
        total=len(CONFIRMED) + len(UNRESOLVED),
        unresolved=len(UNRESOLVED),
        arrays="\n".join(arrays),
        rows="\n".join(rows),
        helper_rows="\n".join(helper_rows),
        unresolved_rows="\n".join(unresolved_rows),
    )


STRAT_ENUM = {
    "EXACT": "kExact",
    "INPUT_GUARD": "kInputGuard",
    "OBSERVE": "kObserve",
    "DISABLED": "kDisabled",
}


def cmd_check(exe: Path, header: Path) -> int:
    """校验头文件里的 RVA/签名是否仍与目标 exe 匹配。"""
    if not header.is_file():
        print(f"没有可比对的头文件: {header}", file=sys.stderr)
        return 1
    text = header.read_text(encoding="utf-8")
    pe = pefile.PE(str(exe), fast_load=True)

    ts = pe.FILE_HEADER.TimeDateStamp
    m = re.search(r"SATFIX_WIN_EXE_TIMESTAMP 0x([0-9A-Fa-f]+)u", text)
    if m and int(m.group(1), 16) != ts:
        print(f"PE 时间戳不匹配: 头文件 0x{int(m.group(1), 16):08X} vs exe 0x{ts:08X}")
        print("  -> 游戏更新过。需要重新确证 RVA 后重新生成。")
        return 1

    # 解析每个目标的 rva 与签名数组
    sigs: dict[str, list[int]] = {}
    for mm in re.finditer(r"kSig_(\w+)\[SATFIX_WIN_SIG_LEN\] = \{ ([^}]*) \};", text):
        sigs[mm.group(1)] = [int(x, 16) for x in mm.group(2).split(",")]

    bad = 0
    for mm in re.finditer(
        r'\{\s*"(\w+)",\s*"[^"]*",\s*0x([0-9a-f]+)u,\s*kSig_(\w+),\s*k(\w+),', text
    ):
        key, rva_hex, signame = mm.group(1), mm.group(2), mm.group(3)
        rva = int(rva_hex, 16)
        want = sigs.get(signame)
        if want is None:
            print(f"  {key}: 找不到签名数组 kSig_{signame}")
            bad += 1
            continue
        got = read_sig(pe, rva, len(want))
        if got != want:
            print(f"  {key}: RVA 0x{rva:08x} 的序言签名不匹配")
            print(f"      期望 {' '.join(f'{b:02x}' for b in want)}")
            print(f"      实际 {' '.join(f'{b:02x}' for b in got)}")
            bad += 1
        else:
            print(f"  {key}: RVA 0x{rva:08x} 签名一致（{len(want)} 字节）")

    if bad:
        print(f"\n{bad} 个目标不再匹配 -> 游戏更新后必须重新确证。")
        return 1
    print("\n全部目标签名一致。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).resolve().parent
    ap.add_argument("--exe", type=Path, default=Path(DEFAULT_EXE))
    ap.add_argument("--out", type=Path, default=here.parent / "src" / "satfix_targets_win.generated.hpp")
    ap.add_argument("--check", action="store_true", help="只校验，不写文件")
    args = ap.parse_args()

    if not args.exe.is_file():
        sys.exit(f"找不到 exe: {args.exe}")

    if args.check:
        return cmd_check(args.exe, args.out)

    text = build(args.exe)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"已写入 {args.out}")
    print(f"  确证 {len(CONFIRMED)} 个目标 + {len(HELPERS)} 个辅助函数，未定位 {len(UNRESOLVED)} 个")
    return 0


if __name__ == "__main__":
    sys.exit(main())
