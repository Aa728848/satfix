//
// sat_guard —— 用 shk 把 Stellaris 的定点算术接上饱和处理
//
// 默认是**影子模式**：只观测、只打日志，绝不改游戏数值。
// 打开 -DSATFIX_REPLACE=1 才会在检出问题时回写。
//
// 两批 hook：
//   A. 修正系统的乘法出口（数值放大主链）
//        CModifier::ApplyModifierMult 的两个重载
//   B. CFixedPoint 全部 9 个非内联成员
//        Sqrt / SafeSqrt×2 / GetRounded×2 / GetRounded64 / RoundTo / Atan2 / operator fpml
//
//   （CFixedPoint 的 operator+ - * / 没有符号、全是内联，hook 不到；
//     反编译里 `... / 100000` 就地展开 2551 处，只能靠 hook 关口间接覆盖。）
//
// 每种 hook 的策略分三类，代码里用注释标了：
//   EXACT        —— 有精确的饱和参考实现，可逐位比对、可替换
//   INPUT_GUARD  —— 危险在输入域，先把输入夹到安全域再调原函数
//   OBSERVE      —— 只能判定"是否进入危险域"，只记日志（默认不替换）
//
// 编译：
//   ./build.sh           影子模式
//   ./build.sh replace   打开回写
//
// 运行：
//   LD_PRELOAD=$PWD/sat_guard.so ./stellaris
//

#include "shk.hpp"
#include "stl_fix.hpp"
#include "satfix_targets.generated.hpp"
#include "debug_ui.hpp"

#include <atomic>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#ifndef SATFIX_REPLACE
#define SATFIX_REPLACE 0
#endif

#ifndef SATFIX_MAX_LOGS
#define SATFIX_MAX_LOGS 500
#endif

namespace {

using namespace stlfix;

// ---------------------------------------------------------------------------
// 目标表（由 tools/gen_targets.py 生成）
// ---------------------------------------------------------------------------
struct Target
{
    const char* key;
    const char* symbol;
    uintptr_t addr;
    const char* desc;
};

const Target kTargets[] = {
#define SATFIX_ROW(key, sym, addr, desc) {#key, sym, static_cast<uintptr_t>(addr), desc},
    SATFIX_TARGETS(SATFIX_ROW)
#undef SATFIX_ROW
};

constexpr size_t kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

// 辅助函数表（只解析调用，不 hook）——同样由 gen_targets.py 生成
const Target kHelpers[] = {
#define SATFIX_HROW(key, sym, addr, desc) {#key, sym, static_cast<uintptr_t>(addr), desc},
    SATFIX_HELPERS(SATFIX_HROW)
#undef SATFIX_HROW
};

constexpr size_t kHelperCount = sizeof(kHelpers) / sizeof(kHelpers[0]);

// ---------------------------------------------------------------------------
// 统计与日志
// ---------------------------------------------------------------------------
std::atomic<uint64_t> g_calls{0};
std::atomic<uint64_t> g_events{0};
std::atomic<uint64_t> g_logs{0};

// 每个 hook 的调用计数 —— 用来回答"hook 到底有没有在被调用"。
// 只装上了不等于会被调用：游戏走到主菜单之前，很多函数一次都不会进。
enum : size_t
{
    kIdxApplyMulCfx,
    kIdxApplyMulFp15,
    kIdxSqrt,
    kIdxSafeSqrt,
    kIdxSafeSqrtInt,
    kIdxGetRounded,
    kIdxGetRounded64,
    kIdxRoundTo,
    kIdxAtan2,
    kIdxGetRoundedFp15,
    kIdxToFp15,
    kIdxVarMultiply,
    kIdxVarAdd,
    kIdxMpe15,
    kIdxMpe7,
    kIdxDiploWeight,
    kIdxShieldMax,
    kIdxArmorMax,
    kIdxHullMax,
    kIdxCount
};

const char* const kIdxNames[kIdxCount] = {
    "ApplyModifierMult(cfx)",  "ApplyModifierMult(fp15)", "Sqrt()",
    "SafeSqrt()",              "SafeSqrt(long long)",     "GetRounded()",
    "GetRounded64()",          "RoundTo()",               "Atan2()",
    "GetRounded(fp15)",        "operator fpml",
    "multiply_variable",       "add_variable",
    "MilitaryPowerExp<15>",    "MilitaryPowerExp<7>",     "DiplomaticWeight",
    "CalcMaxShieldHitPoints",
    "CalcMaxArmorHitPoints",   "CalcMaxHitPoints",
};

std::atomic<uint64_t> g_fn_calls[kIdxCount];
std::atomic<bool> g_fn_seen[kIdxCount];
uint64_t g_heartbeat_every = 0;   ///< SATFIX_HEARTBEAT=N，0 = 关

void maybe_heartbeat(uint64_t total)
{
    if(g_heartbeat_every == 0 || (total % g_heartbeat_every) != 0)
        return;
    std::fprintf(stderr, "[satfix] --- heartbeat: %" PRIu64 " 次调用，各类计数 ---\n",
                 (uint64_t)total);
    for(size_t i = 0; i < kIdxCount; ++i)
    {
        const uint64_t n = g_fn_calls[i].load(std::memory_order_relaxed);
        if(n != 0)
            std::fprintf(stderr, "[satfix]     %-24s %" PRIu64 "\n", kIdxNames[i], n);
    }
    std::fprintf(stderr, "[satfix]     累计 EVENT(溢出) = %" PRIu64 "\n",
                 g_events.load(std::memory_order_relaxed));
}

inline void bump(size_t idx)
{
    const uint64_t total = g_calls.fetch_add(1, std::memory_order_relaxed) + 1;
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    // 每个 hook 第一次被真正调用时打一行 —— 回答"装上了"和"真的在被调用"
    // 是两件事：游戏走到主菜单之前，很多函数一次都不会进。
    // 有界输出（最多 11 行），所以默认就开着。
    if(!g_fn_seen[idx].exchange(true, std::memory_order_relaxed))
        std::fprintf(stderr, "[satfix] 首次调用: %s\n", kIdxNames[idx]);
    maybe_heartbeat(total);
}

/// 打日志（前 SATFIX_MAX_LOGS 条），格式： [satfix] EVENT <函数> <详情>
void note(const char* fn, const char* fmt, ...)
{
    ++g_events;
    if(g_logs.fetch_add(1, std::memory_order_relaxed) >= SATFIX_MAX_LOGS)
        return;
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(detail, sizeof detail, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "[satfix] EVENT %-18s %s\n", fn, detail);
}

/// 硬编码地址只对当前 build 有效（非 PIE，地址固定）。
/// 装之前确认地址真的在映射里，否则在别的进程里会把内存写坏。
bool is_mapped(uintptr_t addr)
{
    FILE* f = std::fopen("/proc/self/maps", "r");
    if(f == nullptr)
        return false;
    char line[512];
    bool found = false;
    while(std::fgets(line, sizeof line, f) != nullptr)
    {
        unsigned long lo = 0, hi = 0;
        if(std::sscanf(line, "%lx-%lx", &lo, &hi) == 2 && addr >= lo && addr < hi)
        {
            found = true;
            break;
        }
    }
    std::fclose(f);
    return found;
}

void* resolve_target(const Target& t)
{
    if(void* p = shk::resolve(t.symbol))
        return p;
    if(t.addr == 0)
    {
        std::fprintf(stderr, "[satfix] %s: 没在二进制里找到，跳过\n", t.desc);
        return nullptr;
    }
    if(!is_mapped(t.addr))
    {
        std::fprintf(stderr,
                     "[satfix] %s: 符号解析失败，且 0x%lx 不在本进程映射里"
                     "（不是在 stellaris 里跑，或者游戏版本变了 —— "
                     "跑 tools/gen_targets.py <binary> 重新生成）\n",
                     t.desc, static_cast<unsigned long>(t.addr));
        return nullptr;
    }
    std::fprintf(stderr, "[satfix] %s 符号解析失败，退回硬编码地址 0x%lx\n",
                 t.desc, static_cast<unsigned long>(t.addr));
    return reinterpret_cast<void*>(t.addr);
}

template <class Hook>
bool install_at(const Target& t, Hook& hook, typename Hook::fn_t detour)
{
    void* addr = resolve_target(t);
    if(addr == nullptr)
        return false;
    if(!hook.install(addr, detour))
    {
        std::fprintf(stderr, "[satfix] FAILED to hook %s\n", t.desc);
        return false;
    }
    std::fprintf(stderr, "[satfix] hooked %-50s @ %p\n", t.desc, addr);
    return true;
}

const Target& target(const char* key)
{
    for(size_t i = 0; i < kTargetCount; ++i)
        if(std::strcmp(kTargets[i].key, key) == 0)
            return kTargets[i];
    static const Target none{"?", "?", 0, "?"};
    return none;
}

const Target& helper(const char* key)
{
    for(size_t i = 0; i < kHelperCount; ++i)
        if(std::strcmp(kHelpers[i].key, key) == 0)
            return kHelpers[i];
    static const Target none{"?", "?", 0, "?"};
    return none;
}

// ===========================================================================
// A. 修正系统的乘法出口
//
//   语义（4.5.2 反编译 962696 / 962872）：
//     m     = 从 mods 里按 type 查到的值（查不到按 0）；flag 时取 -m
//     mult  = max(1.0 + m, minMult(type))
//     *value = (*value * mult) / 100000          ← CFixedPoint 版
//     *value = (*value * mult_fp15) >> 15        ← fpml 版
//     return mult;                               ← ★ 返回值就是实际倍率
//
//   所以不用解析修正表：value 是 in-place 引用，返回值就是倍率。
// ===========================================================================

using ApplyMulFn = int64_t (*)(void* value, const void* mods, int32_t type, bool flag);

shk::TypedHook<ApplyMulFn> g_apply_mul_cfx;
shk::TypedHook<ApplyMulFn> g_apply_mul_fp15;

// EXACT
int64_t hook_apply_mul_cfx(void* value, const void* mods, int32_t type, bool flag)
{
    if(value == nullptr)
        return g_apply_mul_cfx.call(value, mods, type, flag);
    auto* slot = static_cast<int64_t*>(value);
    const int64_t v0 = *slot;
    const int64_t mult = g_apply_mul_cfx.call(value, mods, type, flag);
    const int64_t v_game = *slot;
    bump(kIdxApplyMulCfx);

    const int64_t v_sat = cfx::mul(v0, mult);
    if(v_game != v_sat)
    {
        note("ApplyModifierMult", "type=%d flag=%d v0=%" PRId64 " (%.4f) mult=%" PRId64
                                  " (%.4f) game=%" PRId64 " sat=%" PRId64,
             type, flag ? 1 : 0, (long long)v0, static_cast<double>(v0) / 1e5,
             (long long)mult, static_cast<double>(mult) / 1e5,
             (long long)v_game, (long long)v_sat);
#if SATFIX_REPLACE
        *slot = v_sat;
#endif
    }
    return mult;
}

// EXACT（fpml 版：返回值是十进制倍率，乘法在 2^15 编码上做）
int64_t hook_apply_mul_fp15(void* value, const void* mods, int32_t type, bool flag)
{
    if(value == nullptr)
        return g_apply_mul_fp15.call(value, mods, type, flag);
    auto* slot = static_cast<int64_t*>(value);
    const int64_t v0 = *slot;
    const int64_t mult = g_apply_mul_fp15.call(value, mods, type, flag);
    const int64_t v_game = *slot;
    bump(kIdxApplyMulFp15);

    const int64_t v_sat = mul_shift_sat(v0, cfx::to_fp15(mult), 15);
    if(v_game != v_sat)
    {
        note("ApplyModifierMult15", "type=%d flag=%d v0=%" PRId64 " mult=%" PRId64
                                    " game=%" PRId64 " sat=%" PRId64,
             type, flag ? 1 : 0, (long long)v0, (long long)mult,
             (long long)v_game, (long long)v_sat);
#if SATFIX_REPLACE
        *slot = v_sat;
#endif
    }
    return mult;
}

// ===========================================================================
// B. CFixedPoint 的 9 个非内联成员
// ===========================================================================

using CfxSelfFn  = int64_t (*)(const void* self);            ///< this 版本，返回 CFixedPoint/整数
using SsqrtIntFn = int64_t (*)(int64_t p);                   ///< 静态 SafeSqrt(long long)
using RoundToFn  = int64_t (*)(void* self, const void* div); ///< 非静态 + in-place
using Atan2Fn    = int64_t (*)(const void* a, const void* b);///< 静态

shk::TypedHook<CfxSelfFn>  g_sqrt;
shk::TypedHook<CfxSelfFn>  g_safe_sqrt;
shk::TypedHook<SsqrtIntFn> g_safe_sqrt_int;
shk::TypedHook<CfxSelfFn>  g_get_rounded;
shk::TypedHook<CfxSelfFn>  g_get_rounded64;
shk::TypedHook<RoundToFn>  g_round_to;
shk::TypedHook<Atan2Fn>    g_atan2;
shk::TypedHook<CfxSelfFn>  g_get_rounded_fp15;

/// ⚠️ sret 返回（RDI=返回槽，RSI=this），见 hook_to_fp15 的注释
using OpFp15Fn = void (*)(void* sret, const void* self);
shk::TypedHook<OpFp15Fn>   g_to_fp15;

int64_t load_i64(const void* p) { int64_t v; std::memcpy(&v, p, sizeof v); return v; }
void store_i64(void* p, int64_t v) { std::memcpy(p, &v, sizeof v); }

// --- EXACT：GetRounded / GetRounded64 ---------------------------------------
// 游戏公式: x>=0 ? (x+50000)/100000 : -((50000-x)/100000)
// 溢出点  : x+50000（x→INT64_MAX）、50000-x（x→INT64_MIN）
int64_t hook_get_rounded(const void* self, shk::TypedHook<CfxSelfFn>& hk, const char* name,
                         size_t idx)
{
    const int64_t x = load_i64(self);
    const int64_t got = hk.call(self);
    bump(idx);
    const int64_t sat = cfx::round_to_int_sat(x);
    if(got != sat)
    {
        note(name, "x=%" PRId64 " (%.4f) game=%" PRId64 " sat=%" PRId64,
             (long long)x, static_cast<double>(x) / 1e5, (long long)got, (long long)sat);
#if SATFIX_REPLACE
        return sat;
#endif
    }
    return got;
}

int64_t hook_get_rounded_do(const void* self)
{ return hook_get_rounded(self, g_get_rounded, "GetRounded", kIdxGetRounded); }
int64_t hook_get_rounded64_do(const void* self)
{ return hook_get_rounded(self, g_get_rounded64, "GetRounded64", kIdxGetRounded64); }

// --- EXACT：operator fpml::fixed_point<...,15>() ------------------------------
// 游戏公式: (x%100000)*0x40000000/0xC3500000 + (x/100000)*0x8000
//
// ⚠️ ABI 注意：这个转换运算符返回的是一个**类类型**（fpml::fixed_point<...>），
//    走的是 **sret** —— RDI 是返回槽，RSI 才是 this。反编译也印证了这点：
//      CFixedPoint *operator_cast_to_fixed_point(CFixedPoint *this, long *param_1)
//      { *(long *)this = ...; return this; }        // this 就是返回槽
//    当成"RAX 返回 + 第一个参数是 this"来 hook，会让影子值全是垃圾
//    （2026-10-09 的日志就是这么废掉的）。test/run_abi_check.sh 守住这条。
void hook_to_fp15(void* sret, const void* self)
{
    const int64_t x = load_i64(self);
    g_to_fp15.call(sret, self);           // 原函数把结果写进 sret
    bump(kIdxToFp15);

    const int64_t got = load_i64(sret);
    const int64_t sat = cfx::to_fp15_sat(x);
    if(got != sat)
    {
        note("op_fp15", "x=%" PRId64 " (%.4f) game=%" PRId64 " sat=%" PRId64,
             (long long)x, static_cast<double>(x) / 1e5, (long long)got, (long long)sat);
#if SATFIX_REPLACE
        store_i64(sret, sat);
#endif
    }
}

// --- INPUT_GUARD：SafeSqrt(long long) ---------------------------------------
// 游戏实现: if (p > 0) { local = p * 100000; return SafeSqrt(&local); } return 0;
// 溢出点  : p * 100000（p > 92233720368547 时）
int64_t hook_safe_sqrt_int(int64_t p)
{
    const int64_t guarded = cfx::ssqrt_int_input_guard(p);
    if(guarded != p)
        note("SafeSqrt(long long)", "p=%" PRId64 " (%.4f) 超出安全域 -> 按 %" PRId64 " 计算",
             (long long)p, static_cast<double>(p) / 1e5, (long long)guarded);
    bump(kIdxSafeSqrtInt);
    return g_safe_sqrt_int.call(guarded);
}

// --- INPUT_GUARD：Sqrt() const ----------------------------------------------
// 负数输入会被当成巨大无符号数去迭代，结果无意义。
int64_t hook_sqrt(const void* self)
{
    const int64_t x = load_i64(self);
    bump(kIdxSqrt);
    if(x < 0)
    {
        note("Sqrt", "x=%" PRId64 " (%.4f) 为负 —— 原实现会当无符号迭代",
             (long long)x, static_cast<double>(x) / 1e5);
#if SATFIX_REPLACE
        const int64_t zero = 0;
        return g_sqrt.call(&zero);
#endif
    }
    return g_sqrt.call(self);
}

// --- OBSERVE：SafeSqrt() const ----------------------------------------------
int64_t hook_safe_sqrt(const void* self)
{
    const int64_t x = load_i64(self);
    bump(kIdxSafeSqrt);
    if(x < 0)
        note("SafeSqrt", "x=%" PRId64 " (%.4f) 为负",
             (long long)x, static_cast<double>(x) / 1e5);
    return g_safe_sqrt.call(self);
}

// --- OBSERVE：RoundTo(CFixedPoint const&) -----------------------------------
// 非静态、in-place：把 *this 调整到 divisor 的整数倍，返回商。
// 危险点：divisor == 0（除零）；*this + divisor/2 溢出。
int64_t hook_round_to(void* self, const void* divisor)
{
    const int64_t v0 = load_i64(self);
    const int64_t d = load_i64(divisor);
    bump(kIdxRoundTo);
    if(d == 0)
        note("RoundTo", "v=%" PRId64 " divisor=0 —— 原实现会除零", (long long)v0);
    else
    {
        const int64_t half = (v0 < 0) ? -(d / 2) : (d / 2);
        if((half > 0 && v0 > INT64_MAX - half) || (half < 0 && v0 < INT64_MIN - half))
            note("RoundTo", "v=%" PRId64 " divisor=%" PRId64 " —— v+divisor/2 会溢出",
                 (long long)v0, (long long)d);
    }
    return g_round_to.call(self, divisor);
}

// --- OBSERVE：Atan2(CFixedPoint const&, CFixedPoint const&) -----------------
// 内部要做 a*a / b*b 之类的平方，|参数| > sqrt(INT64_MAX) 时中间量溢出。
int64_t hook_atan2(const void* a, const void* b)
{
    const int64_t va = load_i64(a);
    const int64_t vb = load_i64(b);
    bump(kIdxAtan2);
    const int64_t m = (va < 0 ? -va : va) > (vb < 0 ? -vb : vb) ? (va < 0 ? -va : va)
                                                                : (vb < 0 ? -vb : vb);
    if(m > cfx::kSqrtSafeLimit)
        note("Atan2", "a=%" PRId64 " b=%" PRId64 " —— 中间平方会溢出",
             (long long)va, (long long)vb);
    return g_atan2.call(a, b);
}

// --- OBSERVE：GetRounded(fpml::fixed_point<...,15> const&) ------------------
// fp15 -> 十进制：lVar2 = v>>15，再 lVar2*100000；v 很大时会溢出。
int64_t hook_get_rounded_fp15(const void* v)
{
    const int64_t x = load_i64(v);
    bump(kIdxGetRoundedFp15);
    const int64_t int_part = x >> 15;
    if(int_part > INT64_MAX / cfx::kScale || int_part < INT64_MIN / cfx::kScale)
        note("GetRounded(fp15)", "v=%" PRId64 " (int part %" PRId64 ") —— 换算回十进制会溢出",
             (long long)x, (long long)int_part);
    return g_get_rounded_fp15.call(v);
}

// ===========================================================================
// C. 变量系统、战斗力指数、外交权重
// ===========================================================================

// --- C.1 变量系统 -----------------------------------------------------------
//
// CMultiplyVariableEffect::ExecuteActual（反编译 6574163）的核心是：
//     vars = AccessVariablePointer(scope, this+0xb8)      // 变量名在 this+0xb8
//     if (vars && VariableIsSet(vars, name)) {
//         m  = CFixedPointVariableValue::GetValue(this+0xe8, scope)   // 乘数表达式在 this+0xe8
//         v0 = CVariables::GetVariable(vars, name)
//         lVar8 = (v0 * m) / 100000;                                   // ← 裸乘法，会 wrap
//         CVariables::SetVariable(vars, name, lVar8);
//     }
//
// 所以影子可以完全用游戏自己的辅助函数复算 —— 只解析这几个符号，不 hook 它们。
using AccessVarFn = void* (*)(void* scope, const void* cstring);
using GetVarFn    = int64_t (*)(const void* vars, const void* cstring);
using SetVarFn    = void (*)(void* vars, const void* cstring, int64_t value);
using CfpGetValFn = int64_t (*)(const void* self, void* scope);

AccessVarFn g_access_var = nullptr;  ///< AccessVariablePointer(CEventScope&, CString const&)
GetVarFn    g_get_var    = nullptr;  ///< CVariables::GetVariable(CString const&) const
SetVarFn    g_set_var    = nullptr;  ///< CVariables::SetVariable(CString const&, CFixedPoint)
CfpGetValFn g_cfp_getval = nullptr;  ///< CFixedPointVariableValue::GetValue(CEventScope&) const

using EffectFn = void (*)(const void* self, void* scope);
shk::TypedHook<EffectFn> g_var_multiply;
shk::TypedHook<EffectFn> g_var_add;

/// 取变量当前值；拿不到就把 ok 置 false
int64_t var_read(const void* self, void* scope, void** vars, const void** name, bool* ok)
{
    *ok = false;
    const char* base = static_cast<const char*>(self);
    *name = base + 0xb8;                       // CString 变量名
    *vars = g_access_var(scope, *name);        // CVariables*
    if (*vars == nullptr)
        return 0;
    *ok = true;
    return g_get_var(*vars, *name);
}

// EXACT：multiply_variable
void hook_var_multiply(const void* self, void* scope)
{
    bump(kIdxVarMultiply);
    if(g_access_var == nullptr || g_get_var == nullptr || g_cfp_getval == nullptr)
    {
        g_var_multiply.call(self, scope);
        return;
    }

    void* vars = nullptr;
    const void* name = nullptr;
    bool ok = false;
    const int64_t v0 = var_read(self, scope, &vars, &name, &ok);
    const int64_t m = ok ? g_cfp_getval(static_cast<const char*>(self) + 0xe8, scope) : 0;

    g_var_multiply.call(self, scope);

    if(!ok)
        return;
    const int64_t v1 = g_get_var(vars, name);
    const int64_t sat = cfx::mul(v0, m);
    if(v1 != sat)
    {
        note("multiply_variable",
             "v0=%" PRId64 " (%.4f) x m=%" PRId64 " (%.4f) -> game=%" PRId64 " sat=%" PRId64,
             (long long)v0, static_cast<double>(v0) / 1e5, (long long)m,
             static_cast<double>(m) / 1e5, (long long)v1, (long long)sat);
#if SATFIX_REPLACE
        if(g_set_var != nullptr)
            g_set_var(vars, name, sat);
#endif
    }
}

// EXACT：add_variable（溢出条件更苛刻，但顺手）
void hook_var_add(const void* self, void* scope)
{
    bump(kIdxVarAdd);
    if(g_access_var == nullptr || g_get_var == nullptr || g_cfp_getval == nullptr)
    {
        g_var_add.call(self, scope);
        return;
    }

    void* vars = nullptr;
    const void* name = nullptr;
    bool ok = false;
    const int64_t v0 = var_read(self, scope, &vars, &name, &ok);
    const int64_t d = ok ? g_cfp_getval(static_cast<const char*>(self) + 0xe8, scope) : 0;

    g_var_add.call(self, scope);

    if(!ok)
        return;
    const int64_t v1 = g_get_var(vars, name);
    const int64_t sat = stlfix::saturating_add<int64_t>(v0, d);
    if(v1 != sat)
    {
        note("add_variable",
             "v0=%" PRId64 " + d=%" PRId64 " -> game=%" PRId64 " sat=%" PRId64,
             (long long)v0, (long long)d, (long long)v1, (long long)sat);
#if SATFIX_REPLACE
        if(g_set_var != nullptr)
            g_set_var(vars, name, sat);
#endif
    }
}

// --- C.2 战斗力/军力指数 ----------------------------------------------------
//
// NCombatRules::CalcMilitaryPowerExponent(fpml a, fpml b) 是**静态成员、返回类类型**：
//   RDI = 返回槽(sret)，RSI = a 的地址，RDX = b 的地址
//   （参数是不可平凡拷贝的类，按 invisible reference 传指针）
// 内部是反复的 `lVar6 * lVar9 >> shift`，没有饱和 —— 后期舰队军力足够大时就会 wrap。
//
// OBSERVE：只记录"中间积会撑爆 int64"的调用，不改数值（pow 的等价饱和实现风险高）。
using MpeFn = void (*)(void* sret, const void* a, const void* b);
shk::TypedHook<MpeFn> g_mpe15;
shk::TypedHook<MpeFn> g_mpe7;

void hook_mpe(void* sret, const void* a, const void* b, shk::TypedHook<MpeFn>& hk, size_t idx,
              const char* name)
{
    const int64_t va = load_i64(a);
    const int64_t vb = load_i64(b);
    bump(idx);
    hk.call(sret, a, b);

    const __int128 p = static_cast<__int128>(va) * vb;
    if(p > INT64_MAX || p < INT64_MIN)
        note(name, "a=%" PRId64 " b=%" PRId64 " -> %" PRId64 "（中间积超 int64，已 wrap）",
             (long long)va, (long long)vb, (long long)load_i64(sret));
}

void hook_mpe15(void* sret, const void* a, const void* b)
{ hook_mpe(sret, a, b, g_mpe15, kIdxMpe15, "CalcMilitaryPowerExponent<15>"); }

void hook_mpe7(void* sret, const void* a, const void* b)
{ hook_mpe(sret, a, b, g_mpe7, kIdxMpe7, "CalcMilitaryPowerExponent<7>"); }

// --- C.3 外交权重 -----------------------------------------------------------
//
// CPopJob::CalcDiplomaticWeight(CPopGroup const&) const 返回 CFixedPoint（走 RAX）。
// 权重是各项(经济/科技/舰队…)加权求和，**不可能为负**；用户实测后期舰队部分会溢出，
// 那时返回值会变成负数或量级离谱 —— 这个判据是"有把握"的，不需要复算。
//
// OBSERVE：只记录。
using DiploFn = int64_t (*)(const void* self, const void* group);
shk::TypedHook<DiploFn> g_diplo_weight;

int64_t hook_diplo_weight(const void* self, const void* group)
{
    bump(kIdxDiploWeight);
    const int64_t r = g_diplo_weight.call(self, group);
    // 1e17 = 1e12 游戏单位；正常外交权重到 1e6 量级，这个阈值只抓离谱值
    if(r < 0 || r > 100000000000000000LL)
        note("CalcDiplomaticWeight", "返回 %" PRId64 " (%.4f) —— 权重应为非负，疑似溢出",
             (long long)r, static_cast<double>(r) / 1e5);
    return r;
}

// --- C.4 护盾上限 -----------------------------------------------------------
//
// NShipUtil::CalcMaxShieldHitPoints(CBaseDesignImplementation const&, CModifier const&,
//                                   CFleet const*, CToolTip*)  → 返回 CFixedPoint（RAX）
// 护盾上限是"船体尺寸基础值 × 一连串乘法修正"，其中大量乘法是就地内联的，
// 现有 hook（ApplyModifierMult）抓不到。这里补一个观测点：
// 正常护盾上限一定 ≥ 0，且不会离谱；负数或量级异常 = 几乎必然是 wrap。
using ShieldMaxFn = int64_t (*)(const void* design, const void* mods, const void* fleet,
                                void* tooltip);

/// 装甲/护盾/船体上限的"合理上限"，单位是 CFixedPoint 存储值（1e5 = 1）。
/// 默认 1e11 = 100 万游戏单位 —— 远高于任何正常舰船，只用来兜住溢出后的荒谬值。
/// 真出现合法的大数值，用 SATFIX_MAX_HP_CAP=<游戏单位> 调大。
int64_t g_max_hp_cap = 100000000000LL;

// --- 饱和重实现用的辅助函数（只解析、不 hook） ---
//   CShipSize::GetModifierValue(CModifier const&, ModifierType) const  -> CFixedPoint
//   CBaseDesignImplementation::GetCurrentGrowthStage() const           -> 设计阶段对象
using GetModifierValueFn = int64_t (*)(const void* size, const void* mods, uint32_t type);
using GetGrowthStageFn   = void* (*)(const void* design);
using GetNameFn          = const void* (*)(const void* size);   ///< CShipSize::GetName() const
GetModifierValueFn g_get_modifier_value = nullptr;
GetGrowthStageFn   g_get_growth_stage   = nullptr;
GetNameFn          g_ship_size_get_name = nullptr;

/// 把 CString 转成 char*：PDS 的 CString 在 +0x10 存 data 指针
/// （依据：反编译里读文件名/日志字串处都是 `*(char**)(cstr + 0x10)`）。
/// 这是**未验证的指针追逐**，所以只在 SATFIX_NAME_LOOKUP=1 时才做，且带基本范围检查。
const char* cstring_to_charptr(const void* cstr)
{
    const uintptr_t p = reinterpret_cast<uintptr_t>(cstr);
    if(p < 0x10000)
        return nullptr;
    const char* data = nullptr;
    std::memcpy(&data, static_cast<const char*>(cstr) + 0x10, 8);
    if(reinterpret_cast<uintptr_t>(data) < 0x10000)
        return nullptr;
    return data;
}

shk::TypedHook<ShieldMaxFn> g_shield_max;
shk::TypedHook<ShieldMaxFn> g_armor_max;
shk::TypedHook<ShieldMaxFn> g_hull_max;

int64_t hook_max_hp(const void* design, const void* mods, const void* fleet, void* tooltip,
                    shk::TypedHook<ShieldMaxFn>& hk, size_t idx, const char* name)
{
    bump(idx);
    const int64_t r = hk.call(design, mods, fleet, tooltip);

    // 判据：**等值比对**（重算 vs 原版）。演进（都是实测逼出来的）：
    //   1) 最初用"超过 1e6 游戏单位"当阈值 -> 在用户故意加 +50000000360% 护盾修正的
    //      存档里全是误报（1e12~1e13 是引擎算出的**正确值**）；
    //   2) 退成"结果为负" -> 不误报但抓不全；
    //   3) 现在重实现已忠实（实测 design_base 123200 + 0x2e 1178.75 = 124378.75，
    //      × factor 500000004.60 = 62189375572142.25，与原版 62189375572142 逐位一致），
    //      改用等值比对：不相等 => 原版那一步溢出了。
    //      好处：误差不放大——重实现若差 1 ULP，只会把那台船改 1 ULP。
    int64_t design_base = 0;
    int64_t base = 0, add = 0, factor = 0, sat = -1;
    // ⚠️ 注意：目前只有**护盾**的重算是忠实的。
    //   2026-10-09 实测事故：这个函数被船体/装甲共用，而我写死了护盾的参数
    //   （design+0x130 / 0x2e / 0x2f），于是船体/装甲的"重算"其实在算护盾 →
    //   与原版必然不等 → 三个函数全被误判成溢出（诊断值三者完全相同就是铁证）。
    //   在读出各自的偏移与 type 号之前，船体/装甲一律走退化路径（只认"结果为负"）。
    const bool recompute_ready = (idx == kIdxShieldMax)
                                 && (g_get_modifier_value != nullptr)
                                 && (g_get_growth_stage != nullptr);
    if(recompute_ready)
    {
        void* stage = g_get_growth_stage(design);
        const void* size = (stage != nullptr)
                               ? *reinterpret_cast<const void* const*>(
                                     static_cast<const char*>(stage) + 8)
                               : nullptr;
        if(size != nullptr)
        {
            std::memcpy(&design_base, static_cast<const char*>(design) + 0x130, 8);
            base = saturating_add<int64_t>(design_base, g_get_modifier_value(size, mods, 0x2e));
            add = g_get_modifier_value(size, mods, 0x2f);
            factor = saturating_add<int64_t>(add, cfx::kOne);
            if(factor > 0)
                sat = cfx::mul(base, factor);   // ★ 饱和乘法（__int128 中间量 + 夹取）
        }
    }

    if(sat >= 0)
    {
        if(sat != r)
        {
            // 标识信息：原始指针永远打（零风险）；名字要 SATFIX_NAME_LOOKUP=1 才解引用
            char ident[192];
            const void* size_for_name = nullptr;
            if(g_get_growth_stage != nullptr)
            {
                void* st = g_get_growth_stage(design);
                if(st != nullptr)
                    size_for_name = *reinterpret_cast<const void* const*>(
                        static_cast<const char*>(st) + 8);
            }
            std::snprintf(ident, sizeof ident, " design=%p size=%p",
                          const_cast<void*>(design), const_cast<void*>(size_for_name));
            // ⚠️ 不要再在这里调 CShipSize::GetName()！
            //   2026-10-09 21:35 崩溃：GetName 内部走本地化字符串池
            //   （PdxLocalizeAndReplaceView -> LocalizeString -> PMurHash32），
            //   而本 hook 是在 CPdxTaskScheduler 的工作线程上被调用的
            //   （RecalculateCachedData 并行化），本地化那套不是线程安全的 -> SEGV。
            //   所以只保留零风险的原始指针，名字以后要做的话必须挪到主线程。
            note(name, "重算 != 原版（判定溢出）原版=%" PRId64 " (%.2f) 重算=%" PRId64
                       " (%.2f) [design_base=%.2f base=%.2f add=%.2f factor=%.2f]%s%s",
                 (long long)r, static_cast<double>(r) / 1e5,
                 (long long)sat, static_cast<double>(sat) / 1e5,
                 static_cast<double>(design_base) / 1e5,
                 static_cast<double>(base) / 1e5,
                 static_cast<double>(add) / 1e5,
                 static_cast<double>(factor) / 1e5,
                 ident, SATFIX_REPLACE ? "" : "（影子模式，未改数值）");
#if SATFIX_REPLACE
            return sat;
#endif
        }
        return r;
    }

    // 退化路径（辅助函数没解析到）：只认"结果为负"这条硬判据
    if(r < 0)
    {
        note(name, "结果为负 %" PRId64 " (%.2f) -> 置零%s",
             (long long)r, static_cast<double>(r) / 1e5,
             SATFIX_REPLACE ? "" : "（影子模式，未改数值）");
#if SATFIX_REPLACE
        return 0;
#endif
    }
    return r;
}

int64_t hook_shield_max(const void* d, const void* m, const void* f, void* t)
{ return hook_max_hp(d, m, f, t, g_shield_max, kIdxShieldMax, "CalcMaxShieldHitPoints"); }

int64_t hook_armor_max(const void* d, const void* m, const void* f, void* t)
{ return hook_max_hp(d, m, f, t, g_armor_max, kIdxArmorMax, "CalcMaxArmorHitPoints"); }

int64_t hook_hull_max(const void* d, const void* m, const void* f, void* t)
{ return hook_max_hp(d, m, f, t, g_hull_max, kIdxHullMax, "CalcMaxHitPoints"); }

// ===========================================================================
// 安装
// ===========================================================================
/// LD_PRELOAD 会被子进程继承（cream.sh 里那些 cp/rm/bash 都会加载我们）。
/// 只有真正的游戏进程才值得干活，其余静默退出 —— 否则一次启动刷几百行日志。
bool is_stellaris_process()
{
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
    if(n <= 0)
        return false;
    buf[n] = '\0';
    const char* base = std::strrchr(buf, '/');
    base = (base != nullptr) ? base + 1 : buf;
    return std::strcmp(base, "stellaris") == 0 || std::strcmp(base, "stellaris.exe") == 0;
}

void install_hooks()
{
    // SATFIX_FORCE=1 用于离线回归（test/run_abi_check.sh 把 sat_guard 加载进
    // 一个假游戏进程，那时 /proc/self/exe 当然不叫 stellaris）
    if(!is_stellaris_process() && std::getenv("SATFIX_FORCE") == nullptr)
    {
        if(std::getenv("SATFIX_VERBOSE"))
            std::fprintf(stderr,
                         "[satfix] 本进程不是 stellaris，跳过"
                         "（LD_PRELOAD 被 cream.sh 的子进程继承了，属正常现象）\n");
        return;
    }

    std::fprintf(stderr, "[satfix] targets from %s (version %s, %s)\n",
                 SATFIX_TARGETS_BINARY, SATFIX_TARGETS_VERSION, SATFIX_TARGETS_FOUND);
    std::fprintf(stderr, "[satfix] shadow mode = %s\n",
                 SATFIX_REPLACE ? "REPLACE (会改数值)" : "SHADOW (只观测)");

    if(const char* hb = std::getenv("SATFIX_HEARTBEAT"))
    {
        g_heartbeat_every = std::strtoull(hb, nullptr, 10);
        if(g_heartbeat_every != 0)
            std::fprintf(stderr, "[satfix] 心跳：每 %" PRIu64 " 次调用打一次汇总\n",
                         g_heartbeat_every);
    }

    const char* failed[16];
    int nfail = 0, n = 0;
    auto try_install = [&](const Target& t, auto& hook, auto detour) {
        if(install_at(t, hook, detour))
            ++n;
        else if(nfail < 16)
            failed[nfail++] = t.desc;
    };

    // A. 修正系统乘法出口
    try_install(target("apply_mul_cfx"),        g_apply_mul_cfx, &hook_apply_mul_cfx);
    try_install(target("apply_mul_fp15"),       g_apply_mul_fp15, &hook_apply_mul_fp15);
    // B. CFixedPoint 的 9 个非内联成员
    try_install(target("cfx_sqrt"),             g_sqrt, &hook_sqrt);
    try_install(target("cfx_safe_sqrt"),        g_safe_sqrt, &hook_safe_sqrt);
    try_install(target("cfx_safe_sqrt_int"),    g_safe_sqrt_int, &hook_safe_sqrt_int);
    try_install(target("cfx_get_rounded"),      g_get_rounded, &hook_get_rounded_do);
    try_install(target("cfx_get_rounded64"),    g_get_rounded64, &hook_get_rounded64_do);
    try_install(target("cfx_round_to"),         g_round_to, &hook_round_to);
    try_install(target("cfx_atan2"),            g_atan2, &hook_atan2);
    try_install(target("cfx_get_rounded_fp15"), g_get_rounded_fp15, &hook_get_rounded_fp15);
    try_install(target("cfx_to_fp15"),          g_to_fp15, &hook_to_fp15);

    // C. 变量系统 / 战斗力指数 / 外交权重
    // 变量那两个 hook 依赖游戏自己的辅助函数，先解析（只解析，不 hook）
    // 符号名来自生成的 SATFIX_HELPERS 表，拼错会被 gen_targets.py --list 抓到
    struct HelperBind
    {
        const char* key;
        void** slot;
    };
    const HelperBind bindings[] = {
        {"access_var_pointer", reinterpret_cast<void**>(&g_access_var)},
        {"cvars_get",          reinterpret_cast<void**>(&g_get_var)},
        {"cvars_set",          reinterpret_cast<void**>(&g_set_var)},
        {"cfp_getvalue",       reinterpret_cast<void**>(&g_cfp_getval)},
    };
    int nvarhelp = 0;
    for(const HelperBind& b : bindings)
    {
        const Target& h = helper(b.key);
        void* p = resolve_target(h);
        *b.slot = p;
        if(p != nullptr)
        {
            ++nvarhelp;
            if(std::getenv("SATFIX_VERBOSE"))
                std::fprintf(stderr, "[satfix]   辅助 %s -> %p\n", h.desc, p);
        }
        // 解析失败时 resolve_target 已经打过具体是哪个符号了
    }
    if(nvarhelp < static_cast<int>(kHelperCount))
        std::fprintf(stderr,
                     "[satfix] 变量系统辅助函数只解析到 %d/%zu —— "
                     "multiply_variable/add_variable 会退化成纯透传（只计数，不做影子）\n",
                     nvarhelp, kHelperCount);

    try_install(target("var_multiply"), g_var_multiply, &hook_var_multiply);
    try_install(target("var_add"),      g_var_add, &hook_var_add);
    try_install(target("mpe15"),        g_mpe15, &hook_mpe15);
    try_install(target("mpe7"),         g_mpe7, &hook_mpe7);
    try_install(target("diplo_weight"), g_diplo_weight, &hook_diplo_weight);
    // 饱和重实现要用的辅助函数（只解析）
    g_get_modifier_value = shk::resolve_as<GetModifierValueFn>(
        "_ZNK9CShipSize16GetModifierValueERK9CModifier12ModifierType");
    g_get_growth_stage = shk::resolve_as<GetGrowthStageFn>(
        "_ZNK25CBaseDesignImplementation21GetCurrentGrowthStageEv");
    // g_ship_size_get_name 保留解析但**不再调用**（线程不安全，见 hook_max_hp 注释）
    g_ship_size_get_name = shk::resolve_as<GetNameFn>("_ZNK9CShipSize7GetNameEv");
    if(g_get_modifier_value == nullptr || g_get_growth_stage == nullptr)
        std::fprintf(stderr,
                     "[satfix] 护盾上限的饱和重实现辅助函数没解析全（%p/%p），"
                     "溢出时退回夹取\n",
                     (void*)g_get_modifier_value, (void*)g_get_growth_stage);

    try_install(target("shield_max"), g_shield_max, &hook_shield_max);
    try_install(target("armor_max"), g_armor_max, &hook_armor_max);
    try_install(target("hull_max"), g_hull_max, &hook_hull_max);
    if(const char* cap = std::getenv("SATFIX_MAX_HP_CAP"))
    {
        const double units = std::strtod(cap, nullptr);
        if(units > 0.0)
        {
            g_max_hp_cap = static_cast<int64_t>(units * 1e5);
            std::fprintf(stderr, "[satfix] 上限夹取阈值 = %.1f 游戏单位\n", units);
        }
    }

    // D. ImGui 调试窗口（debug_target_weight）
    //   群星自带 ImGui 且符号导出，这里只是 hook 它的 NewFrame 画自己的窗口
    if(satfix_ui::install())
        ++n;

    if(n == 0)
        std::fprintf(stderr, "[satfix] 没有任何 hook 装上 —— 什么都没改，游戏正常继续\n");
    else
        std::fprintf(stderr, "[satfix] 共装上 %d 个 hook（%zu 个符号目标 + ImGui 调试窗口）\n",
                     n, kTargetCount);

    for(int i = 0; i < nfail; ++i)
    {
        std::fprintf(stderr, "[satfix] 未装上: %s\n", failed[i]);
        if(std::strstr(failed[i], "SafeSqrt(long long)") != nullptr)
            std::fprintf(stderr,
                         "[satfix]   ↑ 已知原因：该函数序言是 `push; test; jle rel8`，"
                         "蹦床复制后 rel8 够不到原目标，shk 拒绝安装（不是版本问题）\n");
    }
}

/// ★ 必须用全局对象的构造函数安装（见 hooklib/README.md §3.1）：
///   __attribute__((constructor)) 会被同一编译单元的静态初始化覆盖掉。
struct AutoInstall
{
    AutoInstall() { install_hooks(); }
};

AutoInstall g_auto_install;

}  // namespace

/// 调试/自动化用的查询入口（gdb 里 `call satfix_stats(&c,&e)` 或者以后接 SIGUSR1）
extern "C" void satfix_stats(uint64_t* calls, uint64_t* events, uint64_t* logs)
{
    if(calls) *calls = g_calls.load();
    if(events) *events = g_events.load();
    if(logs) *logs = g_logs.load();
}
