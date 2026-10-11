// ===========================================================================
//  自动生成，不要手改 —— 由 tools/gen_targets_win.py 产出
//
//  来源二进制 : D:\Steam\steamapps\common\Stellaris\stellaris.exe
//  文件大小   : 44948088 字节
//  PE TimeDateStamp : 0x6ABEAA3F
//  ImageBase  : 0x140000000
//  生成时间   : 2026-10-11 22:51:20
//  确证目标   : 18/19（另有 1 个尚未定位）
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

#define SATFIX_WIN_EXE_TIMESTAMP 0x6ABEAA3Fu
#define SATFIX_WIN_IMAGE_BASE    0x140000000ull
#define SATFIX_WIN_SIG_LEN       16
#define SATFIX_WIN_FOUND         "18/19"
#define SATFIX_WIN_UNRESOLVED    1

namespace satfix_win {

enum Strategy : uint8_t {
  kExact      = 0,   ///< 有精确饱和参考实现，可逐位比对、可替换
  kInputGuard = 1,   ///< 危险在输入域：先把输入夹到安全域再调原函数
  kObserve    = 2,   ///< 只判定"是否进入危险域"，只记日志
  kDisabled   = 3,   ///< 地址已确证但 ABI 未确认 -> 拒绝安装（安全失败）
};

struct Target {
  const char*     key;
  const char*     desc;
  uint32_t        rva;        ///< 相对 ImageBase
  const uint8_t*  sig;        ///< 序言签名（SATFIX_WIN_SIG_LEN 字节）
  uint8_t         strategy;
  const char*     evidence;   ///< 形状证据（怎么确证的）
};

/// 只解析地址、不装钩子的辅助函数。
struct Helper {
  const char*     key;
  const char*     desc;
  uint32_t        rva;
  const uint8_t*  sig;
  const char*     evidence;
};

inline const uint8_t kSig_cfx_get_rounded[SATFIX_WIN_SIG_LEN] = { 0x48, 0x8b, 0x01, 0x48, 0x8d, 0x88, 0xb0, 0x3c, 0xff, 0xff, 0x48, 0x85, 0xc0, 0x78, 0x07, 0x48 };
inline const uint8_t kSig_cfx_to_fp15[SATFIX_WIN_SIG_LEN] = { 0x4c, 0x8b, 0x01, 0x4c, 0x8b, 0xd2, 0x49, 0xbb, 0x09, 0xe1, 0xd1, 0xc6, 0x11, 0x6b, 0xf1, 0x29 };
inline const uint8_t kSig_apply_mul_cfx[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0x8b, 0xfa, 0x48, 0x8b, 0xd9 };
inline const uint8_t kSig_apply_mul_fp15[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0x8b, 0xfa, 0x48, 0x8b, 0xd9 };
inline const uint8_t kSig_cfx_round_to[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7c, 0x24, 0x18, 0x48 };
inline const uint8_t kSig_cfx_atan2[SATFIX_WIN_SIG_LEN] = { 0x41, 0x56, 0x4c, 0x8b, 0x12, 0x4c, 0x8b, 0xf1, 0x48, 0x89, 0x5c, 0x24, 0x10, 0x4d, 0x8b, 0xca };
inline const uint8_t kSig_var_multiply[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x6c, 0x24, 0x20, 0x56, 0x57, 0x41, 0x56, 0x48, 0x81 };
inline const uint8_t kSig_var_add[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0x55, 0x56, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xf2, 0x48 };
inline const uint8_t kSig_cfx_get_rounded_fp15[SATFIX_WIN_SIG_LEN] = { 0x48, 0x8b, 0x02, 0x4c, 0x8b, 0xc1, 0x48, 0x85, 0xc0, 0x7e, 0x05, 0x48, 0x8b, 0xd0, 0xeb, 0x18 };
inline const uint8_t kSig_shield_max[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0x4c, 0x89, 0x4c, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41 };
inline const uint8_t kSig_armor_max[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0x4c, 0x89, 0x4c, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41 };
inline const uint8_t kSig_hull_max[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };
inline const uint8_t kSig_cfx_sqrt[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x4c, 0x24, 0x08, 0x41, 0x54, 0x41, 0x57, 0x48, 0x83, 0xec, 0x18, 0x4c, 0x8b, 0x3a };
inline const uint8_t kSig_cfx_safe_sqrt[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x6c, 0x24, 0x20, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83 };
inline const uint8_t kSig_diplo_weight[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x18, 0x55, 0x56, 0x41, 0x56, 0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0x40 };
inline const uint8_t kSig_mpe15[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x8b, 0x0a, 0x49, 0x8b, 0xf8 };
inline const uint8_t kSig_mpe7[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x8b, 0x0a, 0x49, 0x8b, 0xf8 };
inline const uint8_t kSig_damage_per_day[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x18, 0x4c, 0x89, 0x4c, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55 };
inline const uint8_t kSig_access_var_pointer[SATFIX_WIN_SIG_LEN] = { 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48, 0x89, 0x78, 0x18, 0x41 };
inline const uint8_t kSig_cvars_get[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x6c, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55 };
inline const uint8_t kSig_cvars_set[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x4c, 0x89, 0x44, 0x24, 0x18, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48 };
inline const uint8_t kSig_cfp_getvalue[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x4d, 0x8b, 0xd0 };
inline const uint8_t kSig_ship_size_of[SATFIX_WIN_SIG_LEN] = { 0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0x01, 0x48, 0x8b, 0xd9, 0xff, 0x50, 0x10, 0x48 };
inline const uint8_t kSig_modifier_value[SATFIX_WIN_SIG_LEN] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48 };

inline const Target kTargets[] = {
    {"cfx_get_rounded", "CFixedPoint::GetRounded() const  /  GetRounded64() const", 0x01b4c170u, kSig_cfx_get_rounded, kExact, "win dump FUN_141b4c170（17 行）：lVar1=*p1; lVar2=lVar1-50000; if(-1<lVar1) lVar2=lVar1+50000; return lVar2/100000; 与 Linux 的 CFixedPoint::GetRounded/GetRounded64（反编译 8599412/8599430，两函数体**完全相同**）逐字一致。MSVC 的 COMDAT 折叠把这两个相同函数合并成了一份，所以只有一个地址 —— 这与「脚本里查 GetRounded 得 0 命中、GetRounded 形状的孪生只有 1 个」互相印证。已实测溢出：INT64_MAX -> 游戏得 -92233720368547，饱和版 +92233720368547。"},
    {"cfx_to_fp15", "CFixedPoint::operator fpml::fixed_point<long long,48,15>() const", 0x01b4c0a0u, kSig_cfx_to_fp15, kExact, "**ABI 靠调用点确证，不是靠猜**。同族有两个实例，签名不同：(a) FUN_141b4c0a0：*param_2 = ((*param_1 % 100000)*0x40000000)/0xc3500000 + (*param_1/100000)*0x8000；调用点 `FUN_141b4c0a0(&DAT_1431517c8, local_368)` —— **目标是第二个参数**（rbx 里的 sret 槽），源在 rcx（this）。这正是 CFixedPoint::operator fpml<...,15>() const（Linux 反编译 8599274）。(b) FUN_14075a370：*param_1 = ((param_2 % 100000)*0x40000000)/0xc3500000 + (param_2/100000)*0x8000；调用点 `FUN_14075a370(&local_res20, 1000)` —— **第二个参数是标量**（1000/10000/100000/1000000），所以它是另一个带**缩放参数**的换算（反方向：把某个定点值换成另一种刻度），**不是** operator fpml。我最初把 0x75A370 当成 operator fpml 并按「rdx 传值」写 detour，活体探针立刻打脸：四个输入全返回同一个常数 1767657313（连 x=0 都不是 0），因为 rdx 其实是一个缩放标量（我传进去的指针低 32 位成了缩放值）。这条经验值得记：**函数体一样不等于 ABI 一样**，参数含义要看调用点。现在指向 0x1B4C0A0，签名 longlong* fn(longlong* ret /*rdx*/, longlong* src /*rcx*/)。"},
    {"apply_mul_cfx", "CModifier::ApplyModifierMult(CFixedPoint&, CModifier const&, ModifierType, bool)", 0x0036df80u, kSig_apply_mul_cfx, kExact, "**用「调用者」定位成功的**（函数体指纹分不出来，见 5.1）。方法：Linux 侧有 78 个函数调用 ApplyModifierMult，其中 35 个带字符串字面量；取 `CalcStarbaseCapacity`（它的 STARBASE_CAPACITY_MAX_REACHED 唯一命中 Windows dump 的 FUN_14073c540），发现它两次调用 `FUN_14036df80` —— 而后者体内正是`*(DAT_142814390 + 0xa0 + param_4*0xb0)` 的类型表查找 + `(v*m)/100000` + 拆分回退。与 Linux 962696 **逐行对应**：`if (0x7ffffffe < (int)param_4) { *param_1 = 100000; return; }` 对应 `if (param_3 != 0x7fffffff)`；`*param_2 = (v*m)/100000`（**就地改写 CFixedPoint&**）对应 `*param_1 = lVar6`；`*param_1 = local_10; return param_1`（sret 返回**实际倍率**）对应 `return puVar4`。**为什么能做成 EXACT**：它返回实际生效的倍率，所以 detour 可以（1）先读入参 v0，（2）调原函数拿到真实倍率 m_eff，（3）用 cfx::mul 复算精确值并比对，完全**不需要**重新实现 CModifier 的类型表查找 —— 也就绕开了「逆清它内部结构」这个难题。ABI：sret — rcx=返回槽（倍率），rdx=CFixedPoint& 被就地改写，r8=CModifier const*，r9d=ModifierType，第 5 参数(bool)=栈上传。"},
    {"apply_mul_fp15", "CModifier::ApplyModifierMult(fpml::fixed_point<...,15>&, CModifier const&, ModifierType, bool)", 0x0036e0a0u, kSig_apply_mul_fp15, kExact, "与 apply_mul_cfx 地址相邻（0x36E0A0 vs 0x36DF80），是同一族的第二个重载。体内把 `operator fpml::fixed_point<...,15>` **内联**了（所以按「调用 FUN_141b4c0a0」搜不到，我一开始就是这么搜空的）：`*param_2 = (((local_10 % 100000) * 0x40000000) / 0xc3500000 + (local_10 / 100000) * 0x8000) * *param_2 >> 0xf;` —— 与 Linux 962872 的`CFixedPoint::operator_cast_to_fixed_point(...); *param_1 = local_18 * *param_1 >> 0xf;` 一致。同样**返回实际倍率**（`*param_1 = local_10`），所以也能做成 EXACT。ABI：同 apply_mul_cfx，只是第 5 个 bool 参数在这里恒为 0（内联调用）。"},
    {"cfx_round_to", "CFixedPoint::RoundTo(CFixedPoint const&)", 0x01b4c1b0u, kSig_cfx_round_to, kObserve, "win dump FUN_141b4c1b0（31 行）与 Linux CFixedPoint::RoundTo（反编译 8599448）同构：先按 `lVar3 + 0x53e2d6238da3U < 0xa7c5ac471b47` 判量级（0x53e2d6238da3 = 2^62/5 量级的安全界），小量级走 `(lVar3*100000)/200000`、大量级走 `(lVar2%200000)*100000/200000 + (lVar3%100000)*100000/200000` 的拆分路径，最后 `*param_1 = lVar3 - lVar3 % lVar2; return lVar3 / lVar2;` —— 结尾这三行与 Linux 版的 `*(ulong *)this = uVar3 - (long)uVar3 % (long)uVar4; return (long)uVar3 / (long)uVar4;` 逐字对应。**ABI**：非 sret，返回值在 rax；rcx = this（会被就地改写），rdx = 除数(CFixedPoint const&)。**为什么是 OBSERVE**：Linux 侧同样只观测（记录 divisor==0 与 v+divisor/2 溢出），没有写精确饱和参考实现 —— 它的拆分路径要逐位等价重写成本高，先看实机有没有 divisor==0。"},
    {"cfx_atan2", "CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&)", 0x01b4c2d0u, kSig_cfx_atan2, kObserve, "win dump FUN_141b4c2d0（98 行，Linux Atan2 也是这个量级）同时命中 **Atan2 的五个标志常量**：`0x132cb`(= 3.1416/4 × 1e5，Linux 版 `(long)(uVar8 * 0x132cb) / 100000` 用的就是这个)、`0x39863`(= 3.1416 × 1e5，Linux 版的 `lVar5 = 0x39863`)、`0x53e2d6238da3`、以及安全域常量 `0xb504f333`/`0x16a09e667`。五个常量同时出现，是这一族里最强的一次指纹命中。**ABI**：sret(param_1=rcx 返回槽, param_2=rdx 第一个 CFixedPoint, param_3=r8 第二个)。**为什么是 OBSERVE**：Linux 侧同样只观测（记录参数平方会溢出的量级），原因写在 Linux README 第 5 节：Atan2 是多项式逼近，重写逐位等价参考实现成本高且容易错。"},
    {"var_multiply", "CMultiplyVariableEffect::ExecuteActual(CEventScope&) const", 0x01777f00u, kSig_var_multiply, kObserve, "**RVA 已更正 —— 旧的 0x00231640 装错了函数，见下。**确证方式（字符串 + 调用者语义）：Linux 版 CMultiplyVariableEffect::ExecuteActual （反编译 6574198-6574255）里有一条独占的诊断串 `multiply_variable: variable %s is not set for scoped %s '%s' at %s`。在 Windows dump 里按该串检索，**唯一命中 FUN_141777f00**。体形也逐条对上：先 FUN_1409f7df0(scope, this+0xc0) 取变量（= Linux 的 AccessVariablePointer）、变量未设时走上面那条串、否则 FUN_14034d500(this+0xf0,…) 取 CFixedPointVariableValue::GetValue（= Linux 的 (this+0xe8)，MSVC 把值成员排到 0xf0）、FUN_140227390 取当前值（= CVariables::GetVariable）、FUN_1407aae10(…, v*d/1e5) 写回（= CVariables::SetVariable）。四个 helper 的对应关系是从 Linux 的调用序一一对出来的，不是猜的。**旧 RVA 为什么错**：0x00231640 体内有 `type*0xb0 + 0x9c + DAT_142814390` 的 CModifier 类型表掩码查表，并就地累加 `*(param_1+0x38)` 的 0x10 步长数组 —— 那是 CModifier 惯用法，**不是变量系统**；它既没有那条诊断串，也没有上面四个 helper。（真正的 CModifier 放大出口是 apply_mul_cfx=0x36DF80，那条路已经单独确证。）ABI：void fn(this /*rcx*/, CEventScope* /*rdx*/)。"},
    {"var_add", "CAddVariableEffect::ExecuteActual(CEventScope&) const", 0x01777800u, kSig_var_add, kObserve, "确证方式（调用者法 + 体形比对）：先用**已确证的** var_multiply（0x1777F00）提取出它调用的 4 个 helper RVA（0x9F7DF0 / 0x34D500 / 0x227390 / 0x7AAE10），再在 dump 里找「同时调用这 4 个」的函数 —— 命中 6 个（正是变量效果家族），其中**不含乘法安全域常量 0xb504f333 的 26 行成员有两个**：0x1777800 与 0x1777C80。读体区分：0x1777800 写回 `local_res18[0] + lVar2`（= 值 + 当前变量，加法），0x1777C80 写回 `lVar2 - local_res18[0]`（= 当前变量 - 值，减法）。对照 Linux：CAddVariableEffect::ExecuteActual（6573500）写回 `puVar2 + lVar3` （= GetValue 的返回值 + GetVariable 的返回值，**纯加法、无符号处理**），而 CSubtractVariableEffect 走的是另一套（带减法语义）。所以 0x1777800 = CAddVariableEffect。**为什么是 OBSERVE 而不是 EXACT**：Linux 侧虽然列 EXACT，但它的 EXACT 依赖**先读到 v0**（hook 前 GetVariable）再复算饱和加法；Windows 上 v0 的读取路径是 FUN_140227390 + 名字 CString 布局，尚未验证，贸然 EXACT 会写坏存档。先用 OBSERVE 计数、看实机量级，确认 helper 语义后再升级。ABI：void fn(this /*rcx*/, CEventScope* /*rdx*/)。"},
    {"cfx_get_rounded_fp15", "CFixedPoint::GetRounded(fpml::fixed_point<long long,48,15> const&)", 0x01b4c100u, kSig_cfx_get_rounded_fp15, kObserve, "win dump FUN_141b4c100（23 行）与 Linux CFixedPoint::GetRounded(fpml::fixed_point<...> const&)（反编译 8599289）结构同构：uVar3 = x<1 ? (-(uint)((x & 0x7fff)!=0) & 0x8000) + x : x; lVar4 = (int)(uVar3 >> 0xf); lVar2 = ((x + lVar4*-0x8000) * 0xc3500000) >> 0xf; *ret = (int)(((lVar2 - (ulonglong)(lVar2<1)) + 0x4000) >> 0xf) + lVar4*100000;四个特征常量（0x8000、0xf、0xc3500000、0x4000）与 Linux 版逐一对上。**为什么是 OBSERVE**：它中间有 (…)*0xc3500000 的 64 位乘，可能与游戏其它定点运算一样在极大输入下 wrap；但 Linux 侧也没为它写精确饱和参考实现（同列为 OBSERVE），所以这里只计数、不判罚，先看实机有没有异常量级。意外收获：它紧邻已确证的 GetRounded（0x1B4C170），说明 CFixedPoint 的成员在 0x1B4C0A0..0x1B4CE80 成簇排布 —— 这是继续定位其余 CFixedPoint 成员的捷径。"},
    {"shield_max", "NShipUtil::CalcMaxShieldHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)", 0x00a11d80u, kSig_shield_max, kExact, "**按「CShipSize 修正类型表偏移」确证，两条独立签名同时命中。**签名一（表偏移）：Linux 版体内有 6 个该表的索引常量 0x1614c/0x16158/0x161fc/0x16208/0x162ac/0x162b8（= ModifierType 枚举值，护盾专用的 7 个修正），逐个在 110843 个函数块里检索，**全部只出现在 FUN_140a11d80**。签名二（结构偏移）：体内从 param_2 读 `+0x130`，与 Linux 反编译 （1335625-1336177，`*(param_9 + 0x130)`）一致。签名三（邻居）：Linux 里 CalcMaxHitPoints/CalcMaxShieldHitPoints/CalcMaxArmorHitPoints 连续排布，Windows 里 FUN_140a112a0/FUN_140a11d80/FUN_140a12910 也连续，且 armor 已由 0x15fec/0x15ff8/0x160a8 独立确证为第三位 —— 位置关系吻合。ABI：sret（体内 `*param_1 = ...` 6 处、`return param_1`），与 Atan2 同形。**为什么是 OBSERVE**：Linux 侧同列 OBSERVE（护盾上限 = 船体尺寸基础值 × 一连串乘法修正，其中大量乘法被内联，现有 ApplyModifierMult 钩子抓不到）。判据：正常护盾上限必 ≥ 0 且 不会离谱；负数或量级异常 = 几乎必然是 wrap。"},
    {"armor_max", "NShipUtil::CalcMaxArmorHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)", 0x00a12910u, kSig_armor_max, kExact, "**本目标的确证强度最高：常量三元组在 110843 个函数块里唯一。**Linux 版体内有装甲专用的表索引常量 0x15fec/0x15ff8/0x160a8；把这三个常量同时作为检索条件扫过全部函数块，**命中数 = 1**，就是 FUN_140a12910。（对比：同族的 hull 用 0x13b7c/0x13b88/0x13c38/0x15398/0x15448，shield 用 0x1614c/0x16158/0x16208/0x162b8 —— 三者的常量集互不相交，所以这个判据不会串台。）签名二：体内从 param_2 读 `+0x70`，与 Linux 反编译 1336255 的 `*(undefined1 **)(param_9 + 0x70)` 逐字对上。ABI：sret（`*param_1 = ...` 6 处、`return param_1`）。**为什么是 OBSERVE**：与 shield 同理，Linux 侧也列为观测点。"},
    {"hull_max", "NShipUtil::CalcMaxHitPoints(CBaseDesignImplementation const&, CModifier const&, CFleet const*, CToolTip*)", 0x00a112a0u, kSig_hull_max, kExact, "**按「CShipSize 修正类型表偏移」确证。**签名一（表偏移）：Linux 版体内有船体专用的 索引常量 0x13b7c/0x13b88/0x13c2c/0x13c38/0x1538c/0x15398/0x1543c/0x15448，逐个检索后 0x13b7c/0x13b88/0x13c38/0x15398/0x15448 **只出现在 FUN_140a112a0**（0x13c2c/0x1538c/0x1543c 在本函数里以其它形式被折叠掉了）。签名二（结构偏移）：体内从 param_2 读 `+0x10`，与 Linux 反编译 （1335070-1335619，`*(param_9 + 0x10)`）一致。签名三（邻居）：它是这三个连续函数里的**第一个**，与 Linux 的排布顺序一致（Linux 1335620 CalcMaxHitPoints → 1336178 CalcMaxShieldHitPoints → 1336667 CalcMaxArmorHitPoints；Windows 0xA112A0 → 0xA11D80 → 0xA12910）。ABI：sret（`*param_1 = ...` 6 处、`return param_1`）。**为什么是 OBSERVE**：与 shield 同理，Linux 侧也列为观测点。"},
    {"cfx_sqrt", "CFixedPoint::Sqrt() const  /  fixed_int64::sqrt(fixed_int64*)", 0x01b489d0u, kSig_cfx_sqrt, kInputGuard, "**用「调用者法」定出来的（与 apply_mul_cfx 同一套路，本轮第二次奏效）。**先找 Linux 里谁调用 Sqrt：只有 CalcDistance(1987515)、SetCardinalPatronAttunement、HackyButSafeSqrt、CalculateTargetRotationAndSpeed 四个。其中 CalcDistance 体内同时调用 Sqrt 与 SafeSqrt，且带一个独特常量 0xf4241(=1000001)；按该常量在 Windows 侧检索得到 3 个候选，其中 FUN_140997d30 含 CFixedPoint 专属魔数 0x29f16b11c6d1e109 与平方安全界 0xb504f333 —— 读体确认它是 CalcDistance 同构体，而它调用的 FUN_141b489d0 正是 Sqrt。**体形确证**（与 Linux 8599313 逐步同构）：`lVar1=*src; if (1 < lVar1) { lVar3 = lVar1/2;`（初始猜测 = x/2）`lVar7 = (lVar1*1000)/100000;`（收敛容差 = sqrt 的 1/100 近似）`do { lVar5 = lVar3*lVar3/100000 - lVar1;`（牛顿残差）`lVar4 = lVar5*100000/(2*lVar3); lVar6 = lVar3 - lVar4; }`（牛顿更新）`while ((lVar7 < lVar5 || lVar5 < -lVar7) && lVar4 != 0 && lVar6 != lVar3);`—— 循环条件与 Linux 的 `(uVar5 < -uVar8 || uVar8 < uVar5) && uVar2 != 0` 逐项对应。ABI：sret（`*param_1 = lVar6; return param_1`）。**注意**：Linux 版返回 ulong（RAX），Windows 版走 sret 写回 —— 同一算法的两种 ABI 表达，所以这里按 Windows 的实际机器码定签名，不照抄 Linux。策略 INPUT_GUARD：Linux 侧的判据是「负输入会被当巨大无符号数迭代，结果无意义」，所以只在 x<0 时记一行。"},
    {"cfx_safe_sqrt", "CFixedPoint::SafeSqrt() const", 0x01b4c600u, kSig_cfx_safe_sqrt, kObserve, "**从上一步的结果顺出来的**：确证 Sqrt(0x1B489D0) 后找它的调用者，发现 FUN_141b4c600 既是「Sqrt 的调用者」又是「被 7 个函数调用的公用入口」。读体与 Linux CFixedPoint::SafeSqrt() const（8599678）**逐行同构**：`if (x < 0x2711)`（=10001，安全域下界）→ `x *= 100`（乘 100 进域）→ `Sqrt(&x)` → `if (r + 0xb504f333 < 0x16a09e667) r = r*10000/100000;`（= r/10）`else` 走 `((r % 100000) * 10000)/100000 + (r/100000)*10000` 的拆分路径；否则（x >= 0x2711）先循环 `while (2999999999 < x) { x = x*1000/100000; n++; }`把 x 缩进域、记下缩放次数 n，算完再 `do { r *= 10; } while (n--)` 补回来。常量 0x2711 / 10000 / 1000 / 2999999999 与 Linux 版**逐个对上**。**为什么是 OBSERVE**：Linux 侧同列 OBSERVE，判据是「x<0 时原实现结果无意义」。ABI：sret（`longlong* fn(longlong* ret /*rcx*/, const longlong* src /*rdx*/)`）。"},
    {"diplo_weight", "CPopJob::CalcDiplomaticWeight(CPopGroup const&) const", 0x00838670u, kSig_diplo_weight, kObserve, "**本轮最有价值的一个 —— 用「NDefines 名字 thunk」定出来的全新方法。**难点背景：这个函数在 Linux 里**没有任何直接调用者**（只有 4 处提及，全是它自己），所以「调用者法」对它无效；而按守卫密度筛出 24 个候选、按结构偏移 `+0x808` 命中 0 个。**突破口**：Paradox 的 NDefines 名字字符串（如 `DIPLOMACY_WEIGHT_POP_BASE`）确实存在于 exe 的 .rdata（VA 0x142360e08）。扫 .text 找 rip-relative 引用它的指令，**各只有 1 处**，落在 0x382580 / 0x3825a0。反汇编那两处是一个 5 指令 thunk：`mov rcx,rdx; lea r9,[全局]; lea rdx,[\"NGameplay\"]; lea r8,[\"<名字>\"]; jmp <注册函数>` —— 于是**名字 -> 全局地址**的对应关系被直接读出来：`DIPLOMACY_WEIGHT_POP_BASE -> 0x143151010`、`DIPLOMACY_WEIGHT_POP_HAPPINESS -> 0x143151008`。再在全部 110843 个函数块里找「同时读这两个全局」的函数 —— **命中数 = 1**，就是本函数。**体形逐条对上 Linux（1177404-1177484）**：`param_3+8` 虚调用（Linux `param_10+8` 的 vtable slot）、`param_1+0x18` 取 CJobType（同偏移）、`param_1+0xec` 计数 / `param_1+0xe0` 数组（**两个偏移与 Linux 完全相同**）、`(arr)[i*2+1] * 100000`、`(lVar4 * DAT_143151010)/100000`（= 乘 POP_BASE）、`FUN_14067eec0(param_3)`（= CPopGroup::HasHappiness）、`(uVar5 * DAT_143151008)/100000`（= 乘 POP_HAPPINESS）、`*(param_3+0x8b0)` 再相乘、最后 `uVar5 + lVar4` 求和并写回 sret。**顺带解答了上轮的疑问**：Linux 读 `param_10+0x808`，Windows 读 `param_3+0x8b0` —— 这就是为什么按 `+0x808` 检索命中 0 个。MSVC 布局差异又一次得到实证。ABI：sret（`*param_2 = uVar5; return param_2`），签名 `longlong* fn(const void* self /*rcx*/, longlong* ret /*rdx*/, const void* group /*r8*/)`。策略 OBSERVE：与 Linux 同 —— 外交权重是各项加权和，**不可能为负**；返回负数或量级离谱就是 wrap 的证据，不需要复算。"},
    {"mpe15", "NCombatRules::CalcMilitaryPowerExponent(fpml::fixed_point<long long,48,15>, fpml::fixed_point<long long,48,15>)", 0x00a0a4a0u, kSig_mpe15, kObserve, "**靠「NDefines 名字法」顺出来的（第三个方法，本轮第二次用它破局）。**上两轮对这个目标完全卡住：调用者法无效（调用者不带独占字符串）、常量法无效（Linux 的 0x15bf1 与 0x7fffffff8000 在 Windows 侧都是 0 次）、递归判据无效（73 个自递归函数里没有一个是它）。本轮先用 NDefines 名字法建出 **2369 个** (名字, 组, 全局地址) 三元组（解析器用已确证的 DIPLOMACY_WEIGHT_POP_BASE/HAPPINESS 做校准，两者地址与前面独立确证的结果**完全一致**，证明解析器可信），于是拿到 `MILITARY_POWER_EXPONENT -> 0x1431505B0`（组 = NShip）。顺着它找到唯一读它的函数 FUN_140a08960，它把这个 define 当**指数**传给 `FUN_140a0a610` —— 那就是幂函数。`FUN_140a0a610` 的移位是 `<<7` / `>>7` / `0x80` / `0x7f`，是 **fp7** 编码，所以它是 mpe7；而它紧邻的 `FUN_140a0a4a0`（同样的体形、同样调用一个 log2 辅助）移位是 `<<0xf` / `>>0xf` / `0x8000` / `0x7fff`，是 **fp15**，即本目标。**编码判定与 Linux 完全吻合**：Linux mpe15 体内的掩码常量是 0x7fffffff8000 / 0xffffffffffff8000（fp15 的 0x7fff/0x8000），Linux mpe7 的是 0x7fffffff80 / 0xffffffffffffff80（fp7 的 0x7f/0x80）。体形也一致：都是「处理负指数 -> 调 log2 辅助 -> 累加收敛循环」，收敛条件都是 `while (sum != next + sum)`（加下一项不再改变和即停）。ABI：sret —— `longlong* fn(longlong* out /*rcx*/, const longlong* base /*rdx*/, const longlong* exp /*r8*/)`。**注意参数顺序**：Linux 版是 (out, 指数, 底数)，Windows 是 (out, 底数, 指数) —— 两者相反。这是本轮第 4 次「同族函数 ABI 顺序不一致」的实例。策略 OBSERVE：Linux 侧同 —— 只记录「中间积会撑爆 int64」的调用，不改数值（pow 的等价饱和实现风险高）。"},
    {"mpe7", "NCombatRules::CalcMilitaryPowerExponent(fpml::fixed_point<long long,56,7>, fpml::fixed_point<long long,56,7>)", 0x00a0a610u, kSig_mpe7, kObserve, "与 mpe15 同源、同一轮确证（见上条）。判据是**编码**：本函数用 `<<7` / `>>7` / `0x80` / `0x7f` / `0xffffffffffffff80`，是 fpml 的 7 位小数编码；而 Linux mpe7 体内的掩码常量正是 0x7fffffff80 / 0xffffffffffffff80 / 0xffffffffffffff00 —— 逐个对上。**额外证据**：唯一读 `MILITARY_POWER_EXPONENT` 的函数 FUN_140a08960 就是调用本函数（不是 0xA0A4A0），且它整条路径都用 `>> 7` / `>> 8` 的移位 —— 说明军力权重那条代码路径确实走 fp7 编码。它还有一个专用的 log2 辅助 FUN_140a0a840（fp7 版），与 mpe15 用的 FUN_140a0a770（fp15 版）成对。ABI 与 mpe15 相同：`longlong* fn(longlong* out, const longlong* base, const longlong* exp)`。策略 OBSERVE，同 Linux。"},
    {"damage_per_day", "NShipUtil::CalcAverageDamagePerDay(CBaseDesignImplementation const&, ...) —— 设计师面板的「伤害」", 0x00a14c60u, kSig_damage_per_day, kExact, "**先错了一次，这里是改正后的结论。**第一版按独占常量 0xb50679d3 在**全库**搜，得到 3 个候选，我挑了行数最接近的 FUN_1403c2910（851 行）—— 那是**错的**：实测打开舰船面板时它算出来的是「单件武器」的倍率（obj+0x98 = 24.5 / 19.5 这类小值），而且面板那个 -4380077663777.92 从来不出现在它里面。**改正方法（更硬的判据）**：三个上限函数（hull 0xA112A0 / shield 0xA11D80 / armor 0xA12910）都在 NShipUtil 片区，所以伤害也该在附近。扫 0xA00000..0xA20000 这 218 个函数，只看「有定点乘法或调 d29f10/d29dd0」的，得到 0xA14C60（614 行）—— 它紧跟 CalcMaxSpeed(0xA14150) 之后。**决定性证据：ModifierType 序列逐个相同**。Linux CalcAverageDamagePerDay 依次调 GetModifierValue 的 type 是 0x3a / 0x40 / 0x168 / 0x41 / 0x1d2 / 0x1d3 / 0x230（7 个）；Windows FUN_140a14c60 是 **完全相同的 7 个、相同顺序**。（对照：先前那个错的 FUN_1403c2910 只用了 0x41/0x168/0x230 三个。）**溢出点**：L594-596 那次 `lVar8 = (plVar10 * plVar13) / 100000` 是裸 64 位乘，没有饱和 —— 面板「总计 × 射速倍率」在这里 wrap。用户实测：总计 15467.84 × 射速 +1000000000000%（= 1e10 倍）= 1.55e14 游戏单位 = 1.55e19 存储值 > INT64_MAX(9.22e18) -> 负值。**为什么是 EXACT**：`r` 就是函数的 sret 返回槽（`return param_1`），**专门用来放返回值**，不是共享结构里的某个字段 —— 写它不会碰到别的统计项。判据本身很硬：伤害 = 总计 × 倍率，**不可能为负**，出现负值或 > 9.2e13 游戏单位就必然是 wrap，直接封顶到 INT64_MAX 即可。实测现场（同一函数连续三次调用）：`*ret = 2078190048`（20781.90，正常）-> `*ret = 1915870600908122664`（19158706009081.23，wrap）。"},
};

inline constexpr int kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

/// 尚未定位的目标 —— **只放一行短摘要**，给启动日志用。
///
/// 为什么不放完整证据：这些证据动辄几百字（含反编译片段、证伪过程），
/// 早先直接塞进这里，结果启动日志被刷成 4000 行上限，把真正有用的
/// 「hooked …」行挤掉了。完整证据在 tools/gen_targets_win.py 的
/// UNRESOLVED 里，要看证据去那里看；辅助函数的证据在 HELPERS 里。
inline const char* const kUnresolved[] = {
    "cfx_safe_sqrt_int  —  CFixedPoint::SafeSqrt(long long)  —— **已判定：Windows 侧无对应代码，非缺口**",
};

inline constexpr int kUnresolvedCount = sizeof(kUnresolved) / sizeof(kUnresolved[0]);

/// 辅助函数：只解析地址，不装钩子。
///
/// 用途：var_add / var_multiply 要做 EXACT，必须能**读回变量的当前值**再复算饱和加法/乘法。
/// 这四个就是那条路径。它们同样带序言签名，游戏更新后会被校验挡下。
inline const Helper kHelpers[] = {
    {"access_var_pointer", "AccessVariablePointer(CEventScope&, CString const&)", 0x009f7df0u, kSig_access_var_pointer, "从 var_multiply 的调用点读出。体内先建字符串 \"local_\" 再 FUN_141b2f670(name, len, 0, \"local_\", 6)（= 拼前缀判断），随后按 CEventScope 是否已绑定分别走 FUN_1403965c0/FUN_140396a90/FUN_140392020 —— 与 Linux AccessVariablePointer 的三分支同构。ABI：longlong fn(scope, name)。"},
    {"cvars_get", "CVariables::GetVariable(CString const&) const", 0x00227390u, kSig_cvars_get, "从 var_multiply 的调用点读出（实参是 vars+8，所以它接的是 CVariables 的哈希表头）。体内 FUN_141b430e0(0, name, len) 算哈希，`(uVar3 & uVar5)*0x40 + *(param_1+8)` 定位桶，再 memcmp 比名字；**返回条目指针**，条目 +0x38 就是 CFixedPoint 值。调用方读 `*(longlong *)(entry + 0x38)` —— 这一条直接给出了变量值的存放偏移。ABI：longlong* fn(vars, out_slot, name)，返回 out_slot。"},
    {"cvars_set", "CVariables::SetVariable(CString const&, CFixedPoint)", 0x007aae10u, kSig_cvars_set, "从 var_multiply 的调用点读出。体内 FUN_1407ab940(vars+8, &entry, hash, name, &value)，当 `local_10 == '\\0'`（条目已存在）时写 `*(entry + 0x38) = value` —— 与 cvars_get 的读偏移 0x38 **互为印证**。ABI：void fn(vars, name, value)。"},
    {"cfp_getvalue", "CFixedPointVariableValue::GetValue(CEventScope&) const", 0x0034d500u, kSig_cfp_getvalue, "从 var_multiply 的调用点读出（实参是 this+0xf0，MSVC 把该值成员排在 0xf0；Linux 是 0xe8）。体内按变量值类型分派后把 CFixedPoint 写进 out 槽。ABI：longlong* fn(this+0xf0, out_slot, scope)，返回 out_slot。"},
    {"ship_size_of", "CShipSize* —— 从 CBaseDesignImplementation 取当前成长阶段的船体尺寸", 0x0030e990u, kSig_ship_size_of, "**护盾/装甲/船体上限做忠实重算的前提。**三个上限函数体内都是 `lVar9 = FUN_14030e990(param_2)` 然后把这个返回值当 CShipSize 传给 GetModifierValue —— 所以它就是 Linux 的 `stage = GetCurrentGrowthStage(design); size = *(stage + 8)` 两步的合并体：体内 `lVar2 = (**(code**)(*param_1 + 0x10))()` 虚调用拿阶段对象，再按 `*(param_1 + 0x52c)` 这个成长阶段下标从 `*(lVar2 + 0x20)` 的 0x110 步长数组里取（越界则回落到第 0 个），取出的 `+8` 字段就是 CShipSize。注意它同时覆盖了 Linux 的 GetCurrentGrowthStage + 解引用，**不需要**再单独定位后者。ABI：void* fn(const void* design) —— 单参数，返回值在 rax。"},
    {"modifier_value", "CShipSize::GetModifierValue(CModifier const&, ModifierType) const", 0x00d29dd0u, kSig_modifier_value, "**重算链的取值原语。**三个上限函数体内反复出现 `FUN_140d29dd0(size, &out, mods, type)`，type 就是 ModifierType （hull 0x1e/0x1f、shield 0x2e/0x2f、armor 0x24/0x25）。体内：按 `*(mods + 0x1c)` 的条目数线性扫 `*(mods + 0x10)` 的 type 数组，命中后取 `*(mods + 0x38) + i*0x10` 的值；若该 type 的位掩码 `(*(DAT_142814390 + type*0xb0 + 0xa8) >> 5 & 1)` 置位，则把结果夹进 [0, 100000]（负数→0，>1.0→1.0）；随后再对 `FUN_140d2c080(size, type)` 查一次「该尺寸的同类修正」并**相加**，写进 `*param_2` 返回。**与 Linux 的差异**：Linux 版是 3 参数返回值在 rax，Windows 是 4 参数 sret （第 2 参数是 out 槽）—— 按 Windows 机器码定签名，不照抄 Linux。ABI：longlong* fn(const void* size /*rcx*/, longlong* out /*rdx*/, const void* mods /*r8*/, int type /*r9d*/)，返回 out。"},
};

inline constexpr int kHelperCount = sizeof(kHelpers) / sizeof(kHelpers[0]);

}  // namespace satfix_win

#endif  // SATFIX_WIN_TARGETS_GENERATED_HPP
