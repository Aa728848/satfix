//
// ABI / 影子逻辑的离线回归测试。
//
//   ./abi_check ./libmock_stellaris.so ../sat_guard.so
//
// 做两件事：
//   1) 用正确语义的 mock 调用被 hook 的函数，**返回值必须原样正确**
//      —— 抓 detour 写坏了返回寄存器 / 参数的情况
//   2) 安全输入下 sat_guard 不应该报任何 EVENT
//      —— 抓 detour 读错参数（比如把 sret 指针当 this）导致影子值算错
//
// 2026-10-09 那次日志就是被第 2 条抓出来的：operator fpml 是 sret 返回，
// 当时当成 RAX 返回处理，于是所有 op_fp15 的影子值都是垃圾。
//
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

namespace {

int g_fail = 0;

void check(bool ok, const char* what)
{
    std::printf("  [%s] %s\n", ok ? " OK " : "FAIL", what);
    if(!ok) ++g_fail;
}

template <class Fn>
Fn sym(void* handle, const char* name)
{
    void* p = dlsym(handle, name);
    if(p == nullptr)
        std::printf("  [FAIL] dlsym(%s): %s\n", name, dlerror());
    return reinterpret_cast<Fn>(p);
}

}  // namespace

int main(int argc, char** argv)
{
    if(argc < 3)
    {
        std::printf("用法: %s <libmock_stellaris.so> <sat_guard.so>\n", argv[0]);
        return 2;
    }

    // mock 必须先用 RTLD_GLOBAL 加载，sat_guard 的构造函数里 dlsym 才找得到它
    void* mock = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if(mock == nullptr)
    {
        std::printf("dlopen(%s) 失败: %s\n", argv[1], dlerror());
        return 2;
    }
    void* guard = dlopen(argv[2], RTLD_NOW | RTLD_GLOBAL);
    if(guard == nullptr)
    {
        std::printf("dlopen(%s) 失败: %s\n", argv[2], dlerror());
        return 2;
    }
    std::printf("两个库都加载完了（sat_guard 的构造函数已跑过）\n\n");

    using ApplyMulFn = int64_t (*)(void*, const void*, int32_t, bool);
    using SelfFn     = int64_t (*)(const void*);
    using ToFp15Fn   = void (*)(void*, const void*);

    // ---- 1) ApplyModifierMult(CFixedPoint&) —— 返回倍率，走 RAX ----
    std::printf("[1] CModifier::ApplyModifierMult(CFixedPoint&, ...)\n");
    {
        auto fn = sym<ApplyMulFn>(mock, "_ZN9CModifier17ApplyModifierMultER11CFixedPointRKS_12ModifierTypeb");
        struct { int64_t mult; } mods{200000};   // 2.0
        int64_t value = 150000;                  // 1.5
        const int64_t ret = fn(&value, &mods, 0x28, false);
        check(ret == 200000, "返回值应是被使用的倍率 200000");
        check(value == 300000, "值应被乘成 300000（1.5 × 2.0）");
    }

    // ---- 2) GetRounded() const —— 返回整数，走 RAX ----
    std::printf("[2] CFixedPoint::GetRounded() const\n");
    {
        auto fn = sym<SelfFn>(mock, "_ZNK11CFixedPoint10GetRoundedEv");
        const int64_t x = 150000;                // 1.5
        check(fn(&x) == 2, "1.5 四舍五入应为 2");
        const int64_t y = 100000;                // 1.0
        check(fn(&y) == 1, "1.0 应为 1");
        const int64_t z = 140000;                // 1.4
        check(fn(&z) == 1, "1.4 应为 1");
    }

    // ---- 3) operator fpml<...,15>() —— **sret** ----
    std::printf("[3] CFixedPoint::operator fpml::fixed_point<...,15>() const（sret）\n");
    {
        auto fn = sym<ToFp15Fn>(mock, "_ZNK11CFixedPointcvN4fpml11fixed_pointIxLh48ELh15EEEEv");
        int64_t out = -1;
        const int64_t one = 100000;              // 1.0
        fn(&out, &one);
        check(out == 32768, "1.0 应换算成 2^15 = 32768");
        const int64_t half = 50000;              // 0.5
        out = -1;
        fn(&out, &half);
        check(out == 16384, "0.5 应换算成 2^14 = 16384");
        const int64_t zero = 0;
        out = -1;
        fn(&out, &zero);
        check(out == 0, "0 应换算成 0");
    }

    // ---- 4) 军力指数（静态 + sret + 指针参数） ----
    std::printf("[4] NCombatRules::CalcMilitaryPowerExponent（sret + 指针参数）\n");
    {
        using MpeFn = void (*)(void*, const void*, const void*);
        auto fn = sym<MpeFn>(mock,
            "_ZN12NCombatRules25CalcMilitaryPowerExponentEN4fpml11fixed_pointIxLh48ELh15EEES2_");
        const int64_t a = 32768;   // 1.0（fp15 编码）
        const int64_t b = 65536;   // 2.0
        int64_t out = -1;
        fn(&out, &a, &b);
        // (1.0 * 2.0) >> 15 = 65536
        check(out == 65536, "1.0 × 2.0 应为 65536（fp15 编码的 2.0）");
        out = -1;
        const int64_t zero = 0;
        fn(&out, &zero, &b);
        check(out == 0, "0 × 2.0 应为 0");
    }

    // ---- 5) 外交权重（普通成员，返回值走 RAX） ----
    std::printf("[5] CPopJob::CalcDiplomaticWeight\n");
    {
        using DiploFn = int64_t (*)(const void*, const void*);
        auto fn = sym<DiploFn>(mock, "_ZNK7CPopJob20CalcDiplomaticWeightERK9CPopGroup");
        int64_t dummy_self = 0, dummy_group = 0;
        check(fn(&dummy_self, &dummy_group) == 0, "mock 返回 0，且没有把返回值写坏");
    }

    // ---- 6) 变量 effect（影子依赖游戏辅助函数，mock 里解析不到 -> 应退化成透传） ----
    std::printf("[6] CMultiplyVariableEffect / CAddVariableEffect\n");
    {
        using EffFn = void (*)(const void*, void*);
        auto mul = sym<EffFn>(mock, "_ZNK23CMultiplyVariableEffect13ExecuteActualER11CEventScope");
        auto add = sym<EffFn>(mock, "_ZNK18CAddVariableEffect13ExecuteActualER11CEventScope");
        int64_t self = 0, scope = 0;
        mul(&self, &scope);
        add(&self, &scope);
        check(true, "两个 effect 调用未崩溃（辅助函数缺失时按纯透传处理）");
    }

    dlclose(guard);
    dlclose(mock);
    std::printf("\n%s (failures=%d)\n",
                g_fail ? "有失败" : "全部通过",
                g_fail);
    std::printf("注意：本测试只验证返回值；\"影子模式有没有误报\"由 run_abi_check.sh 检查 stderr\n");
    return g_fail ? 1 : 0;
}
