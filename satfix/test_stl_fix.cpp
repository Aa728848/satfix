//
// stl_fix.hpp 的对拍测试
//
// 要回答三个问题：
//   A) cfx::mul 是否是"数学真值 + 饱和"？        —— 必须恒成立
//   B) 非溢出域上它和游戏逐位一致吗？             —— 决定影子模式有没有误报
//   C) 游戏到底什么时候给出错误结果？             —— 决定这件事值不值得做
//
// 编译（不依赖游戏，也不需要 xmake）：
//   g++ -O2 -std=c++20 -I. -I<eirin 的 include 目录> -o test_stl_fix test_stl_fix.cpp
//   或直接 ./build.sh
//

#include "stl_fix.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>

namespace {

uint64_t g_rng = 0x243F6A8885A308D3ull;

uint64_t next_u64()
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

int g_fail = 0;

void expect(bool ok, const char* what)
{
    if(!ok)
    {
        ++g_fail;
        std::printf("  [FAIL] %s\n", what);
    }
}

__int128 exact_scaled_mul(int64_t a, int64_t b)
{
    return static_cast<__int128>(a) * b / stlfix::cfx::kScale;
}

bool fits_i64(__int128 v)
{
    return v >= static_cast<__int128>(INT64_MIN) && v <= static_cast<__int128>(INT64_MAX);
}

// 游戏拆分路径里第一项 (X % 100000) * Y 是否安全
bool split_first_term_safe(int64_t X, int64_t Y)
{
    return fits_i64(static_cast<__int128>(X % stlfix::cfx::kScale) * Y);
}

// ---------------------------------------------------------------------------
// A/B/C：随机对拍
// ---------------------------------------------------------------------------
void test_random_equivalence(int rounds)
{
    std::printf("[1] 随机对拍 %d 组\n", rounds);

    int64_t representable = 0, overflowing = 0, diverge = 0, diverge_representable = 0;
    int shown = 0;

    for(int i = 0; i < rounds; ++i)
    {
        // 覆盖 0 ~ 63 位各种量级，符号随机
        const int vb = static_cast<int>(next_u64() % 63);
        const int mb = static_cast<int>(next_u64() % 63);
        int64_t v = static_cast<int64_t>(next_u64() >> (63 - vb));
        int64_t m = static_cast<int64_t>(next_u64() >> (63 - mb));
        if(next_u64() & 1) v = -v;
        if(next_u64() & 1) m = -m;

        const __int128 exact = exact_scaled_mul(v, m);
        const int64_t want = stlfix::saturating_cast<int64_t>(exact);
        const int64_t sat = stlfix::cfx::mul(v, m);
        const int64_t game = stlfix::cfx::mul_game(v, m);

        // (A) 饱和值必须等于"数学真值再饱和"——恒成立
        if(sat != want)
        {
            ++g_fail;
            if(g_fail < 10)
                std::printf("  [FAIL] A: v=%" PRId64 " m=%" PRId64 " sat=%" PRId64
                            " want=%" PRId64 "\n", v, m, sat, want);
        }

        if(fits_i64(exact))
            ++representable;
        else
            ++overflowing;

        // (C) 游戏是否给出与"精确饱和值"不同的结果
        if(game != sat)
        {
            ++diverge;
            if(fits_i64(exact)) ++diverge_representable;
            if(shown < 5)
            {
                ++shown;
                std::printf("    分歧样例 v=%-22" PRId64 " m=%-22" PRId64 "\n"
                            "             game=%-22" PRId64 " sat=%-22" PRId64
                            "  (真值%s放得下)\n",
                            (long long)v, (long long)m, (long long)game, (long long)sat,
                            fits_i64(exact) ? "" : "不");
            }
        }
    }

    std::printf("    真值可表示 %" PRId64 " 组，真值溢出 %" PRId64 " 组\n",
                (long long)representable, (long long)overflowing);
    std::printf("    游戏结果 != 精确饱和值：%lld 组\n", (long long)diverge);
    std::printf("      其中『真值其实放得下、但游戏仍算错』：%lld 组\n",
                (long long)diverge_representable);
}

// ---------------------------------------------------------------------------
// 可证明的安全域：真值可表示 且 拆分首项不溢出 => 游戏必须精确
// ---------------------------------------------------------------------------
void test_safe_domain(int rounds)
{
    std::printf("[2] 安全域断言（真值可表示 且 拆分首项不溢出）\n");
    int64_t checked = 0;
    const int before = g_fail;
    for(int i = 0; i < rounds; ++i)
    {
        const int vb = static_cast<int>(next_u64() % 45);   // 到 2^44
        const int mb = static_cast<int>(next_u64() % 40);
        int64_t v = static_cast<int64_t>(next_u64() >> (63 - vb));
        int64_t m = static_cast<int64_t>(next_u64() >> (63 - mb));
        if(next_u64() & 1) v = -v;
        if(next_u64() & 1) m = -m;

        const __int128 exact = exact_scaled_mul(v, m);
        if(!fits_i64(exact)) continue;

        const int64_t X = (m < v) ? v : m;
        const int64_t Y = (m <= v) ? m : v;
        if(!split_first_term_safe(X, Y)) continue;

        ++checked;
        const int64_t game = stlfix::cfx::mul_game(v, m);
        const int64_t sat = stlfix::cfx::mul(v, m);
        if(game != sat)
        {
            ++g_fail;
            if(g_fail < 10)
                std::printf("  [FAIL] B: v=%" PRId64 " m=%" PRId64
                            " game=%" PRId64 " sat=%" PRId64 "\n",
                            (long long)v, (long long)m, (long long)game, (long long)sat);
        }
    }
    std::printf("    抽查 %lld 组：%s\n", (long long)checked,
                (g_fail == before) ? "游戏与饱和实现全部逐位一致" : "发现不一致");
}

// ---------------------------------------------------------------------------
// 具体案例：游戏什么时候能自救、什么时候不能
// ---------------------------------------------------------------------------
void test_cases()
{
    std::printf("[3] 具体案例\n");
    struct Case
    {
        int64_t v, m;
        const char* note;
    } cases[] = {
        {30000000000LL, 30000000000LL, "30000.0 x 30000.0（真值 9e15 放得下）"},
        {1000000000000000LL, 1000000000LL, "1e10 x 1e4 游戏单位（真值 1e19 放不下）"},
    };
    for(auto& c : cases)
    {
        const __int128 exact = exact_scaled_mul(c.v, c.m);
        const int64_t game = stlfix::cfx::mul_game(c.v, c.m);
        const int64_t sat = stlfix::cfx::mul(c.v, c.m);
        std::printf("    %s\n", c.note);
        std::printf("      v=%.2f m=%.2f  真值(128)=%s\n",
                    static_cast<double>(c.v) / 1e5, static_cast<double>(c.m) / 1e5,
                    fits_i64(exact) ? "可表示" : "不可表示");
        std::printf("      游戏=%-24lld 饱和=%-24lld %s\n",
                    (long long)game, (long long)sat, game == sat ? "(一致)" : "(不一致)");
    }
}

// ---------------------------------------------------------------------------
// fpml 方言：直接复用 eirin::fixed_num
// ---------------------------------------------------------------------------
void test_fpml()
{
    std::printf("[4] fpml 方言（fixed_num<int64_t,__int128,15,false>）\n");

    const auto one = stlfix::fp15(1);
    expect(one.internal_value() == 32768, "fp15(1.0) 内部值不是 2^15");

    const auto r = eirin::saturating_mul(stlfix::fp15(3), stlfix::fp15(4));
    expect(r.internal_value() == 393216, "fp15 3*4 内部值错");

    int mismatch = 0;
    for(int i = 0; i < 20000; ++i)
    {
        const int shift = static_cast<int>(next_u64() % 50);
        const int64_t a = static_cast<int64_t>(next_u64() >> shift) * ((next_u64() & 1) ? -1 : 1);
        const int64_t b = static_cast<int64_t>(next_u64() >> shift) * ((next_u64() & 1) ? -1 : 1);
        if(a == 0 || b == 0) continue;

        const auto lib = eirin::saturating_mul(stlfix::fp15::from_internal_value(a),
                                               stlfix::fp15::from_internal_value(b))
                             .internal_value();
        const int64_t ref = stlfix::mul_shift_sat(a, b, 15);
        if(lib != ref) ++mismatch;
    }
    expect(mismatch == 0, "fp15 与手写 >>15 饱和版不一致");
    std::printf("    fp15(1.0)=%lld, 3*4 内部值=%lld, 对拍 2 万组不一致 %d\n",
                (long long)one.internal_value(), (long long)r.internal_value(), mismatch);
}

// ---------------------------------------------------------------------------
// 十进制 <-> 二进制 换算
// ---------------------------------------------------------------------------
void test_convert()
{
    std::printf("[5] CFixedPoint -> fp15 换算\n");
    expect(stlfix::cfx::to_fp15(100000) == 32768, "to_fp15(1.0) != 2^15");
    expect(stlfix::cfx::to_fp15(50000) == 16384, "to_fp15(0.5) != 2^14");
    std::printf("    to_fp15(1.0)=%lld  to_fp15(0.5)=%lld\n",
                (long long)stlfix::cfx::to_fp15(100000),
                (long long)stlfix::cfx::to_fp15(50000));
}

// ---------------------------------------------------------------------------
// CFixedPoint 几个非内联成员的"精确饱和版"对拍
// ---------------------------------------------------------------------------
void test_math_refs()
{
    std::printf("[6] GetRounded / to_fp15 的饱和参考实现\n");

    // --- GetRounded 的游戏原式（会溢出） ---
    auto game_round = [](int64_t x) -> int64_t {
        if(x >= 0)
            return static_cast<int64_t>(static_cast<uint64_t>(x) + 50000u) / 100000;
        return -(static_cast<int64_t>(50000u - static_cast<uint64_t>(x)) / 100000);
    };

    const int before = g_fail;
    int64_t checked = 0;
    for(int i = 0; i < 200000; ++i)
    {
        const int bits = static_cast<int>(next_u64() % 63);
        int64_t x = static_cast<int64_t>(next_u64() >> (63 - bits));
        if(next_u64() & 1) x = -x;
        if(x > INT64_MAX - 50000 || x < INT64_MIN + 50000) continue;  // 安全域
        ++checked;
        if(game_round(x) != stlfix::cfx::round_to_int_sat(x))
        {
            ++g_fail;
            if(g_fail < 10)
                std::printf("  [FAIL] GetRounded 参考实现不一致 x=%" PRId64 "\n", (long long)x);
        }
    }
    std::printf("    GetRounded 安全域抽查 %lld 组：%s\n", (long long)checked,
                (g_fail == before) ? "一致" : "不一致");

    // 溢出演示：x = INT64_MAX 时原式 (x+50000) 回绕成负数
    const int64_t xmax = INT64_MAX;
    std::printf("    INT64_MAX 的 GetRounded: 原式=%" PRId64 "  饱和=%" PRId64 "\n",
                (long long)game_round(xmax), (long long)stlfix::cfx::round_to_int_sat(xmax));
    expect(stlfix::cfx::round_to_int_sat(xmax) > 0, "INT64_MAX 的饱和 GetRounded 应为正");

    // --- to_fp15 的安全域对拍 ---
    const int before2 = g_fail;
    int64_t checked2 = 0;
    for(int i = 0; i < 200000; ++i)
    {
        const int bits = static_cast<int>(next_u64() % 50);   // 到 2^49
        int64_t x = static_cast<int64_t>(next_u64() >> (63 - bits));
        if(next_u64() & 1) x = -x;
        // 安全域：|x/1e5 * 32768| 不溢出
        if(x / 100000 > INT64_MAX / 0x8000 || x / 100000 < INT64_MIN / 0x8000) continue;
        ++checked2;
        if(stlfix::cfx::to_fp15(x) != stlfix::cfx::to_fp15_sat(x))
        {
            ++g_fail;
            if(g_fail < 10)
                std::printf("  [FAIL] to_fp15 参考实现不一致 x=%" PRId64 "\n", (long long)x);
        }
    }
    std::printf("    to_fp15 安全域抽查 %lld 组：%s\n", (long long)checked2,
                (g_fail == before2) ? "一致" : "不一致");

    // overflow 演示：|x| 超过 2^48 * 1e5 时原式第二项回绕
    const int64_t xbig = 40000000000000000LL;   // 4e16，远超 2^48*1e5 ≈ 2.8e19/… 见输出
    std::printf("    to_fp15(4e16): 原式=%" PRId64 "  饱和=%" PRId64 "\n",
                (long long)stlfix::cfx::to_fp15(xbig),
                (long long)stlfix::cfx::to_fp15_sat(xbig));
}

}  // namespace

int main()
{
    std::printf("=== stl_fix 对拍测试 ===\n");
    test_random_equivalence(2000000);
    test_safe_domain(2000000);
    test_cases();
    test_fpml();
    test_convert();
    test_math_refs();
    std::printf("\n%s (failures=%d)\n", g_fail ? "有失败" : "全部通过", g_fail);
    return g_fail ? 1 : 0;
}
