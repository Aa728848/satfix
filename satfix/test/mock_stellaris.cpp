//
// 假的 "stellaris" —— 用假符号复现 sat_guard 要 hook 的那些函数，
// 让 ABI / 影子逻辑可以离线验证，不用真开游戏。
//
// 关键点：几个函数的**返回值 ABI** 必须和真游戏一致，否则 sat_guard 的
// detour 会读到垃圾（这正是 2026-10-09 那次日志里 op_fp15 全错的原因）。
//
//   CFixedPoint::GetRounded() const        -> 整数，走 RAX
//   CModifier::ApplyModifierMult(...)      -> CFixedPoint，走 RAX
//   CFixedPoint::operator fpml<...,15>()   -> **sret**（RDI=返回槽, RSI=this）
//
// 编译成 libmock_stellaris.so，用 abi_check 加载。
//
#include <cstdint>

namespace {

constexpr int64_t kScale = 100000;   // CFixedPoint: 1.0 = 100000

// 游戏的两条路径版本（见 stl_fix.hpp 的 mul_game 注释）
inline int64_t wrap_mul_i64(int64_t a, int64_t b)
{
    return static_cast<int64_t>(static_cast<uint64_t>(a) * static_cast<uint64_t>(b));
}
inline bool fits_sq(int64_t x) { return x >= -3037000499LL && x <= 3037000499LL; }

inline int64_t game_cfx_mul(int64_t v, int64_t m)
{
    if(fits_sq(v) && fits_sq(m))
        return wrap_mul_i64(v, m) / kScale;
    const int64_t X = (m < v) ? v : m;
    const int64_t Y = (m <= v) ? m : v;
    return wrap_mul_i64(X % kScale, Y) / kScale + wrap_mul_i64(X / kScale, Y);
}

inline int64_t game_round_to_int(int64_t x)
{
    if(x >= 0)
        return static_cast<int64_t>(static_cast<uint64_t>(x) + 50000u) / kScale;
    return -(static_cast<int64_t>(50000u - static_cast<uint64_t>(x)) / kScale);
}

inline int64_t game_to_fp15(int64_t x)
{
    return static_cast<int64_t>(static_cast<__int128>(x % kScale) * 0x40000000 / 0xC3500000)
           + (x / kScale) * 0x8000;
}

// mock 用的"修正表"：{ 倍率 }，让 ApplyModifierMult 有个确定行为
struct MockMods
{
    int64_t mult;
};

}  // namespace

#define MOCK_SYM(name, sym) extern "C" name asm(sym)

// ---------------------------------------------------------------------------
// 1) 修正系统的乘法出口 —— 返回 CFixedPoint（8 字节，走 RAX）
// ---------------------------------------------------------------------------
MOCK_SYM(int64_t mock_apply_mul_cfx(void* value, const void* mods, int32_t type, bool flag),
         "_ZN9CModifier17ApplyModifierMultER11CFixedPointRKS_12ModifierTypeb");
int64_t mock_apply_mul_cfx(void* value, const void* mods, int32_t type, bool flag)
{
    (void)type;
    const int64_t mult = static_cast<const MockMods*>(mods)->mult;
    auto* slot = static_cast<int64_t*>(value);
    if(!flag)
    {
        const int64_t v0 = *slot;
        *slot = game_cfx_mul(v0, mult);          // 和真游戏一样：in-place 改
    }
    return mult;                                  // 和真游戏一样：返回实际倍率
}

MOCK_SYM(int64_t mock_apply_mul_fp15(void* value, const void* mods, int32_t type, bool flag),
         "_ZN9CModifier17ApplyModifierMultERN4fpml11fixed_pointIxLh48ELh15EEERKS_12ModifierTypeb");
int64_t mock_apply_mul_fp15(void* value, const void* mods, int32_t type, bool flag)
{
    (void)type;
    const int64_t mult = static_cast<const MockMods*>(mods)->mult;
    auto* slot = static_cast<int64_t*>(value);
    if(!flag)
        *slot = (game_to_fp15(mult) * *slot) >> 15;   // 真游戏：先 cast 再 *value >> 15
    return mult;
}

// ---------------------------------------------------------------------------
// 2) 返回整数、走 RAX 的
// ---------------------------------------------------------------------------
MOCK_SYM(int64_t mock_get_rounded(const void* self), "_ZNK11CFixedPoint10GetRoundedEv");
int64_t mock_get_rounded(const void* self)
{
    int64_t x;
    __builtin_memcpy(&x, self, 8);
    return game_round_to_int(x);
}

MOCK_SYM(int64_t mock_get_rounded64(const void* self), "_ZNK11CFixedPoint12GetRounded64Ev");
int64_t mock_get_rounded64(const void* self) { return mock_get_rounded(self); }

// ---------------------------------------------------------------------------
// 3) **sret**：RDI = 返回槽，RSI = this
// ---------------------------------------------------------------------------
MOCK_SYM(void mock_to_fp15(void* sret, const void* self),
         "_ZNK11CFixedPointcvN4fpml11fixed_pointIxLh48ELh15EEEEv");
void mock_to_fp15(void* sret, const void* self)
{
    int64_t x;
    __builtin_memcpy(&x, self, 8);
    const int64_t r = game_to_fp15(x);
    __builtin_memcpy(sret, &r, 8);
}

MOCK_SYM(int64_t mock_get_rounded_fp15(const void* v),
         "_ZN11CFixedPoint10GetRoundedERKN4fpml11fixed_pointIxLh48ELh15EEE");
int64_t mock_get_rounded_fp15(const void* v)
{
    int64_t x;
    __builtin_memcpy(&x, v, 8);
    const int64_t ip = x >> 15;
    int64_t rem = x - ip * 0x8000;
    rem = (static_cast<__int128>(rem) * 0xC3500000) >> 15;
    return ip * kScale + rem / 1;
}

// ---------------------------------------------------------------------------
// 4) 其余目标：装上就行，逻辑无所谓（它们在 satfix 里是 OBSERVE/INPUT_GUARD）
// ---------------------------------------------------------------------------
MOCK_SYM(int64_t mock_sqrt(const void* self), "_ZNK11CFixedPoint4SqrtEv");
int64_t mock_sqrt(const void* self) { int64_t x; __builtin_memcpy(&x, self, 8); return x / 2; }

MOCK_SYM(int64_t mock_safe_sqrt(const void* self), "_ZNK11CFixedPoint8SafeSqrtEv");
int64_t mock_safe_sqrt(const void* self) { int64_t x; __builtin_memcpy(&x, self, 8); return x / 2; }

MOCK_SYM(int64_t mock_safe_sqrt_int(int64_t p), "_ZN11CFixedPoint8SafeSqrtEx");
int64_t mock_safe_sqrt_int(int64_t p)
{
    // 故意复刻真游戏 CFixedPoint::SafeSqrt(long long) 的序言形状：
    //   push %rax; test %rdi,%rdi; jle rel8 ...
    // 用来验证 shk 的 rel8→rel32 加宽（不然 hook 装不上）。
    __asm__ volatile(
        "push %%rax\n\t"
        "test %%rdi, %%rdi\n\t"
        "jle 1f\n\t"
        "imul $100000, %%rdi, %%rax\n\t"
        "sar $1, %%rax\n\t"
        "pop %%rcx\n\t"
        "ret\n\t"
        "1:\n\t"
        "xor %%eax, %%eax\n\t"
        "pop %%rcx\n\t"
        "ret\n\t"
        :
        :
        : "rax", "rcx", "cc", "memory");
    __builtin_unreachable();
}

MOCK_SYM(int64_t mock_round_to(void* self, const void* d), "_ZN11CFixedPoint7RoundToERKS_");
int64_t mock_round_to(void* self, const void* d) { (void)self; (void)d; return 0; }

MOCK_SYM(int64_t mock_atan2(const void* a, const void* b), "_ZN11CFixedPoint5Atan2ERKS_S1_");
int64_t mock_atan2(const void* a, const void* b) { (void)a; (void)b; return 0; }

// ---------------------------------------------------------------------------
// 5) 变量 effect / 军力指数 / 外交权重
//    注意 ABI：multiply/add_variable 是普通的 (this, scope)；
//    军力指数是**静态成员 + sret + 两个指针参数**（参数是不可平凡拷贝的类）。
// ---------------------------------------------------------------------------
MOCK_SYM(void mock_var_multiply(const void* self, void* scope),
         "_ZNK23CMultiplyVariableEffect13ExecuteActualER11CEventScope");
void mock_var_multiply(const void* self, void* scope) { (void)self; (void)scope; }

MOCK_SYM(void mock_var_add(const void* self, void* scope),
         "_ZNK18CAddVariableEffect13ExecuteActualER11CEventScope");
void mock_var_add(const void* self, void* scope) { (void)self; (void)scope; }

// 军力指数：sret(RDI) + a(RSI) + b(RDX)，a/b 指向 fpml 值
MOCK_SYM(void mock_mpe15(void* sret, const void* a, const void* b),
         "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh48ELh15EEES2_");
void mock_mpe15(void* sret, const void* a, const void* b)
{
    int64_t va = 0, vb = 0;
    __builtin_memcpy(&va, a, 8);
    __builtin_memcpy(&vb, b, 8);
    const int64_t r = (int64_t)(((__int128)va * vb) >> 15);
    __builtin_memcpy(sret, &r, 8);
}

MOCK_SYM(void mock_mpe7(void* sret, const void* a, const void* b),
         "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh56ELh7EEES2_");
void mock_mpe7(void* sret, const void* a, const void* b)
{
    int64_t va = 0, vb = 0;
    __builtin_memcpy(&va, a, 8);
    __builtin_memcpy(&vb, b, 8);
    const int64_t r = (int64_t)(((__int128)va * vb) >> 7);
    __builtin_memcpy(sret, &r, 8);
}

// 外交权重：普通成员函数，返回值走 RAX
MOCK_SYM(int64_t mock_diplo_weight(const void* self, const void* group),
         "_ZNK7CPopJob20CalcDiplomaticWeightERK9CPopGroup");
int64_t mock_diplo_weight(const void* self, const void* group)
{
    (void)self;
    (void)group;
    return 0;   // 0.0：既不为负也不离谱，影子不该报警
}

// 护盾上限：普通静态函数，返回值走 RAX
MOCK_SYM(int64_t mock_shield_max(const void* d, const void* m, const void* f, void* t),
         "_ZN9NShipUtil22CalcMaxShieldHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip");
int64_t mock_shield_max(const void* d, const void* m, const void* f, void* t)
{
    (void)d; (void)m; (void)f; (void)t;
    return 100000;   // 1.0，正常值，影子不该报警
}

MOCK_SYM(int64_t mock_armor_max(const void* d, const void* m, const void* f, void* t),
         "_ZN9NShipUtil21CalcMaxArmorHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip");
int64_t mock_armor_max(const void* d, const void* m, const void* f, void* t)
{ (void)d; (void)m; (void)f; (void)t; return 100000; }

MOCK_SYM(int64_t mock_hull_max(const void* d, const void* m, const void* f, void* t),
         "_ZN9NShipUtil16CalcMaxHitPointsERK25CBaseDesignImplementationRK9CModifierPK6CFleetP8CToolTip");
int64_t mock_hull_max(const void* d, const void* m, const void* f, void* t)
{ (void)d; (void)m; (void)f; (void)t; return 100000; }
