//
//  test_stl_fix_win.cpp —— Windows 定点饱和算术的离线对拍
//
//  移植自 satfix/test_stl_fix.cpp，换了 128 位后端（satfix128.hpp），并新增
//  两节 Windows 侧独有的验证：
//
//     [0] 128 位层自身的穷举/边界验证（saturate 的 2^64 边界是最容易写错的地方）
//     [4] fpml 移位方言 vs 一个独立实现（把 128 位拆成两半手算）—— 交叉验证
//     [6] 用测试向量复现 Linux 侧 README 第 3 节的结论（GetRounded 溢出实例）
//
//  要求：failures == 0。不通过就别进游戏。
//

#include "stl_fix_win.hpp"
#include "satfix_decision.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <random>

using namespace stlfix;

namespace {

int g_fail = 0;
int g_checked = 0;

void expect(bool ok, const char* what) {
  ++g_checked;
  if (!ok) {
    ++g_fail;
    std::printf("  [FAIL] %s\n", what);
  }
}

// ---------------------------------------------------------------------------
// 独立参考实现：只用 uint64 / int64 手算 128 位，故意不复用 satfix128.hpp
// （否则就是自己验证自己）。
// ---------------------------------------------------------------------------

struct Ref128 {
  bool neg;
  uint64_t hi;
  uint64_t lo;
};

Ref128 ref_mul(int64_t a, int64_t b) {
  const bool na = a < 0, nb = b < 0;
  Ref128 r{na != nb, 0, 0};
  const uint64_t ua = na ? (uint64_t)(-(a + 1)) + 1u : (uint64_t)a;
  const uint64_t ub = nb ? (uint64_t)(-(b + 1)) + 1u : (uint64_t)b;
  // 拆成 32 位块手乘
  const uint64_t a0 = ua & 0xffffffffull, a1 = ua >> 32;
  const uint64_t b0 = ub & 0xffffffffull, b1 = ub >> 32;
  const uint64_t p00 = a0 * b0;
  const uint64_t p01 = a0 * b1;
  const uint64_t p10 = a1 * b0;
  const uint64_t p11 = a1 * b1;
  uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull);
  r.lo = (p00 & 0xffffffffull) | (mid << 32);
  r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
  return r;
}

// 参考：把 Ref128 按 (a*b)/d 语义饱和
int64_t ref_mul_div_sat(int64_t a, int64_t b, uint64_t d) {
  Ref128 m = ref_mul(a, b);
  // 256 位被除数的高位补 0（幅值非负），做 128/64 长除
  uint64_t q_hi = m.hi / d;
  uint64_t rem = m.hi % d;
  // q_lo = (rem:lo) / d —— 用 32 位块手算，避免依赖 _udiv128
  uint64_t q_lo = 0;
  {
    // 逐位长除（慢但显然正确；只在测试里用）
    uint64_t r = rem;
    for (int bit = 63; bit >= 0; --bit) {
      // r 始终 < d，左移一位不会溢出（d <= 2^63 量级时 r < 2^63）
      const uint64_t bitval = (m.lo >> bit) & 1ull;
      const bool top = (r >> 63) != 0;
      r = (r << 1) | bitval;
      if (top || r >= d) {
        r -= d;
        q_lo |= (1ull << bit);
      }
    }
  }
  if (!m.neg) {
    if (q_hi != 0 || q_lo > (uint64_t)INT64_MAX) return INT64_MAX;
    return (int64_t)q_lo;
  }
  if (q_hi != 0 || q_lo > 0x8000000000000000ull) return INT64_MIN;
  if (q_lo == 0x8000000000000000ull) return INT64_MIN;
  return -(int64_t)q_lo;
}

// 参考：算术语义
inline int64_t ref_add_sat(int64_t a, int64_t b) {
  const __int64 r = (__int64)((unsigned __int64)a + (unsigned __int64)b);
  if (b > 0 && r < a) return INT64_MAX;
  if (b < 0 && r > a) return INT64_MIN;
  return r;
}

std::mt19937_64 g_rng(0xC0FFEE);

// ---------------------------------------------------------------------------
// [0] 128 位层：边界 + 随机
// ---------------------------------------------------------------------------
void test_int128_layer() {
  std::printf("[0] satfix128 层：边界与随机\n");

  const int64_t mn = INT64_MIN, mx = INT64_MAX;

  // saturate 的关键边界
  expect(sf128::saturate({0, 0}) == 0, "saturate(0) == 0");
  expect(sf128::saturate({0, (uint64_t)mx}) == mx, "saturate(INT64_MAX) == INT64_MAX");
  expect(sf128::saturate({0, (uint64_t)mx + 1}) == mx, "saturate(2^63) 上溢到 INT64_MAX");
  expect(sf128::saturate({~0ull, ~0ull}) == -1,
         "saturate(hi=-1,lo=2^64-1) == -1  <== hi==-1 并不代表下溢");
  expect(sf128::saturate({~0ull, 0x8000000000000000ull}) == mn,
         "saturate(hi=-1,lo=2^63) == INT64_MIN（正好 -2^63）");
  expect(sf128::saturate({~0ull, 0x7fffffffffffffffull}) == mn,
         "saturate(hi=-1,lo=2^63-1) == INT64_MIN（值是 -2^63-1，差一点就越界）");
  expect(sf128::saturate({~0ull, 0}) == mn, "saturate(-2^64) 下溢到 INT64_MIN");
  expect(sf128::saturate({0x8000000000000000ull, 0}) == mn, "saturate(-2^63) == INT64_MIN");

  // 有符号乘积的边界
  expect(sf128::mul_div_sat(mn, 1, 1) == mn, "mul_div_sat(INT64_MIN,1,1) 不 UB");
  expect(sf128::mul_div_sat(mn, -1, 1) == mx, "mul_div_sat(INT64_MIN,-1,1) 饱和到 MAX");
  expect(sf128::mul_div_sat(mx, mx, 1) == mx, "mul_div_sat(MAX,MAX,1) 饱和到 MAX");
  expect(sf128::mul_div_sat(mx, mn, 1) == mn, "mul_div_sat(MAX,MIN,1) 饱和到 MIN");
  expect(sf128::mul_div_sat(0, mn, 1) == 0, "mul_div_sat(0,MIN) == 0");
  expect(sf128::mul_div_sat(-7, 3, 2) == -10, "mul_div_sat(-7,3,2) == -21/2 == -10（向零）");
  expect(sf128::mul_div_sat(7, 3, 2) == 10, "mul_div_sat(7,3,2) == 21/2 == 10");

  // 随机 vs 独立参考
  int bad = 0;
  for (int i = 0; i < 200000; ++i) {
    const int sb = (int)(g_rng() % 64);
    const int tb = (int)(g_rng() % 64);
    int64_t a = (int64_t)(g_rng() >> (63 - sb));
    int64_t b = (int64_t)(g_rng() >> (63 - tb));
    if (g_rng() & 1) a = -a;
    if (g_rng() & 1) b = -b;
    const uint64_t d = 1 + (g_rng() % 1000000);
    if (sf128::mul_div_sat(a, b, d) != ref_mul_div_sat(a, b, d)) ++bad;
  }
  expect(bad == 0, "mul_div_sat 随机 20 万组 == 独立参考");
  if (bad) std::printf("        不一致 %d 组\n", bad);

  int bad2 = 0;
  for (int i = 0; i < 100000; ++i) {
    int64_t a = (int64_t)g_rng(), b = (int64_t)g_rng();
    if (sf128::add_sat(a, b) != ref_add_sat(a, b)) ++bad2;
  }
  expect(bad2 == 0, "add_sat 随机 10 万组 == 独立参考");

  // 移位：与「先算幅值再右移」对比（>15 位不丢位的随机组）
  int bad3 = 0;
  for (int i = 0; i < 100000; ++i) {
    const int sb = (int)(g_rng() % 40);
    const int tb = (int)(g_rng() % 40);
    int64_t a = (int64_t)(g_rng() >> (63 - sb));
    int64_t b = (int64_t)(g_rng() >> (63 - tb));
    if (g_rng() & 1) a = -a;
    if (g_rng() & 1) b = -b;
    // 真值 (a*b) 有符号右移 15：用 long double 只能近似，所以改用精确路径校验：
    // |a*b| < 2^62 时 int64 直接算得出来，可以直接比
    const long double la = (long double)a * (long double)b;
    if (la > 9.0e18L || la < -9.0e18L) continue;  // 超出 int64，跳过
    const int64_t exact = (int64_t)a * (int64_t)b;
    if (sf128::mul_sar_sat(a, b, 15) != (exact >> 15)) ++bad3;
  }
  expect(bad3 == 0, "mul_sar_sat 在 int64 可表示区间内 == 原生 >>15");
}

// ---------------------------------------------------------------------------
// [1] cfx::mul：饱和值必须等于「数学真值再饱和」
// ---------------------------------------------------------------------------
void test_cfx_mul(int rounds) {
  std::printf("[1] cfx::mul 饱和语义 %d 组\n", rounds);

  int bad = 0;
  int64_t representable = 0, overflowing = 0, diverge = 0, diverge_repr = 0;

  for (int i = 0; i < rounds; ++i) {
    const int vb = (int)(g_rng() % 63);
    const int mb = (int)(g_rng() % 63);
    int64_t v = (int64_t)(g_rng() >> (63 - vb));
    int64_t m = (int64_t)(g_rng() >> (63 - mb));
    if (g_rng() & 1) v = -v;
    if (g_rng() & 1) m = -m;

    const int64_t want = ref_mul_div_sat(v, m, cfx::kScale);
    const int64_t sat = cfx::mul(v, m);
    const int64_t game = cfx::mul_game(v, m);

    if (sat != want) {
      ++bad;
      if (bad < 6)
        std::printf("        [FAIL] v=%" PRId64 " m=%" PRId64 " sat=%" PRId64
                    " want=%" PRId64 "\n", v, m, sat, want);
    }

    // 真值是否放得下：用参考实现的 hi 判断
    const Ref128 r = ref_mul(v, m);
    const bool fits = (r.hi == 0 && r.lo / cfx::kScale <= (uint64_t)INT64_MAX &&
                       !(r.neg && r.lo / cfx::kScale > 0x8000000000000000ull));
    if (fits) ++representable; else ++overflowing;

    if (game != sat) {
      ++diverge;
      if (fits) ++diverge_repr;
    }
  }

  expect(bad == 0, "cfx::mul 与「真值再饱和」逐位一致");
  std::printf("        真值可表示 %" PRId64 " 组，溢出 %" PRId64 " 组\n",
              representable, overflowing);
  std::printf("        游戏实现与饱和实现分歧 %" PRId64 " 组（其中真值本可表示 %" PRId64 " 组）\n",
              diverge, diverge_repr);
}

// ---------------------------------------------------------------------------
// [2] 已确证的溢出实例：GetRounded
// ---------------------------------------------------------------------------
void test_get_rounded() {
  std::printf("[2] GetRounded 溢出实例（Linux README 第 3 节的可复现结论）\n");

  // 游戏原式：`x + 50000` 是**有符号 64 位加**，越界就 wrap
  // —— 这正是 GetRounded 的 bug 所在，所以参考实现必须照做，
  //    用无符号加法会把它"修好"，反而复现不出被证实的那次溢出。
  auto game_round = [](int64_t x) -> int64_t {
    if (x < 0) {
      const int64_t t = (int64_t)(50000u - (uint64_t)x);  // 等价于 50000 - x 的 wrap 结果
      return -(t / cfx::kScale);                          // 有符号除法
    }
    const int64_t t = (int64_t)((uint64_t)x + 50000u);    // 有符号溢出 -> wrap
    return t / cfx::kScale;
  };

  // 交叉校验参考实现本身：常规量级下它就是普通四舍五入
  int refbad = 0;
  for (int64_t x = -300000; x <= 300000; x += 1237) {
    const int64_t want = (x >= 0) ? (x + 50000) / 100000 : -((50000 - x) / 100000);
    if (game_round(x) != want) ++refbad;
  }
  expect(refbad == 0, "参考实现本身在常规量级下就是标准四舍五入");

  const int64_t g = game_round(INT64_MAX);
  const int64_t s = cfx::round_to_int_sat(INT64_MAX);
  std::printf("        INT64_MAX: game=%" PRId64 "  sat=%" PRId64 "\n", g, s);
  expect(g == -92233720368547LL, "游戏把 INT64_MAX 舍入成负数（-92233720368547）");
  expect(s == 92233720368547LL, "饱和版给出正确的 92233720368547");
  expect(g != s, "两者确实不同（这就是被证实的溢出）");

  // INT64_MIN 方向：`50000 - x` 溢出，把巨大的负数变成巨大的正数
  const int64_t gmin = game_round(INT64_MIN);
  const int64_t smin = cfx::round_to_int_sat(INT64_MIN);
  std::printf("        INT64_MIN: game=%" PRId64 "  sat=%" PRId64 "\n", gmin, smin);
  expect(gmin == 92233720368547LL, "游戏把 INT64_MIN 舍入成正数（+92233720368547）");
  expect(smin == -92233720368547LL, "饱和版给出正确的 -92233720368547");
  expect(gmin != smin, "两个方向都被证实会溢出（符号整体翻转）");

  // 0 与普通值两边必须一致
  int bad = 0;
  for (int64_t x = -300000; x <= 300000; x += 7919) {
    if (game_round(x) != cfx::round_to_int_sat(x)) ++bad;
  }
  expect(bad == 0, "常规量级下饱和版与游戏原式一致（只在大数处才分歧）");
}

// ---------------------------------------------------------------------------
// [3] to_fp15：证明它溢出不了
// ---------------------------------------------------------------------------
void test_to_fp15() {
  std::printf("[3] to_fp15：验证「换算溢出不了」这个结论\n");

  auto game_to_fp15 = [](int64_t x) -> int64_t {
    return (int64_t)(((int64_t)(x % cfx::kScale) * 0x40000000) / 0xC3500000) +
           (x / cfx::kScale) * 0x8000;
  };

  int bad = 0, oneshot = 0;
  for (int i = 0; i < 300000; ++i) {
    int64_t x = (int64_t)g_rng();
    if (g_rng() & 1) x = -x;
    const int64_t g = game_to_fp15(x);
    const int64_t s = cfx::to_fp15_sat(x);
    if (g != s) {
      ++bad;
      if (bad < 4) std::printf("        [FAIL] x=%" PRId64 " game=%" PRId64 " sat=%" PRId64 "\n", x, g, s);
    }
    if (s == INT64_MAX || s == INT64_MIN) ++oneshot;
  }
  expect(bad == 0, "to_fp15_sat 与游戏原式一致（含 INT64_MAX/MIN 极值）");
  expect(cfx::to_fp15_sat(INT64_MAX) == game_to_fp15(INT64_MAX), "to_fp15(INT64_MAX) 一致");
  expect(cfx::to_fp15_sat(INT64_MIN) == game_to_fp15(INT64_MIN), "to_fp15(INT64_MIN) 一致");
  if (oneshot) std::printf("        （有 %d 组被饱和，理论上不该出现）\n", oneshot);
}

// ---------------------------------------------------------------------------
// [4] fpml 移位方言 vs 手算交叉验证
// ---------------------------------------------------------------------------
void test_fpml() {
  std::printf("[4] fpml 移位方言（>>15 / >>7）\n");

  // 参考：saturate(floor(a*b / 2^sh))。
  // 幅值 = (r.hi:r.lo)；算术右移 = 向下取整，所以负数要 -ceil(mag/2^sh)，
  // 即幅值商在有余数时补 1。
  auto ref_shift = [](int64_t a, int64_t b, unsigned sh) -> int64_t {
    const Ref128 r = ref_mul(a, b);

    // 幅值商 q = floor(mag / 2^sh)（低 64 位）；q_over 表示商本身超出 64 位
    uint64_t q = 0;
    bool q_over = false;
    if (sh == 0) {
      q = r.lo;
      q_over = (r.hi != 0);
    } else if (sh < 64) {
      q = (r.lo >> sh) | (r.hi << (64 - sh));
      q_over = (r.hi >> sh) != 0;
    } else {
      // sh >= 64：商 <= mag/2^64 <= 2^63-1，装得下 64 位
      q = (sh >= 128) ? 0 : (r.hi >> (sh - 64));
      q_over = false;
    }

    // 是否有被丢掉的余数位
    bool rem = false;
    if (sh != 0) {
      if (sh < 64) {
        rem = (r.lo & ((1ull << sh) - 1ull)) != 0;
      } else if (sh < 128) {
        rem = (r.lo != 0) || ((r.hi & ((1ull << (sh - 64)) - 1ull)) != 0);
      } else {
        rem = true;
      }
    }

    if (q_over) return r.neg ? INT64_MIN : INT64_MAX;

    uint64_t m = q;
    if (r.neg && rem) ++m;  // -ceil()
    if (!r.neg) return (m > (uint64_t)INT64_MAX) ? INT64_MAX : (int64_t)m;
    if (m > 0x8000000000000000ull) return INT64_MIN;
    if (m == 0x8000000000000000ull) return INT64_MIN;
    return -(int64_t)m;
  };

  // 先用「原生 64 位能算准」的区间校验参考实现本身，避免拿错参考去测代码
  {
    int refbad = 0;
    for (int i = 0; i < 100000; ++i) {
      const int sb = (int)(g_rng() % 30), tb = (int)(g_rng() % 30);
      int64_t a = (int64_t)(g_rng() >> (63 - sb));
      int64_t b = (int64_t)(g_rng() >> (63 - tb));
      if (g_rng() & 1) a = -a;
      if (g_rng() & 1) b = -b;
      const int64_t exact = a * b;  // |a|,|b| < 2^30 -> 乘积 < 2^60，不溢出
      if (ref_shift(a, b, 15) != (exact >> 15)) ++refbad;
      if (ref_shift(a, b, 7) != (exact >> 7)) ++refbad;
    }
    expect(refbad == 0, "参考 ref_shift 在 int64 可表示区间内 == 原生算术右移");
  }

  int bad15 = 0, bad7 = 0;
  for (int i = 0; i < 200000; ++i) {
    const int sb = (int)(g_rng() % 60), tb = (int)(g_rng() % 60);
    int64_t a = (int64_t)(g_rng() >> (63 - sb));
    int64_t b = (int64_t)(g_rng() >> (63 - tb));
    if (g_rng() & 1) a = -a;
    if (g_rng() & 1) b = -b;
    const int64_t got15 = mul_shift_sat(a, b, kFp15Shift);
    const int64_t ref15 = ref_shift(a, b, 15);
    if (got15 != ref15) {
      if (bad15 < 4)
        std::printf("        [15] a=%" PRId64 " b=%" PRId64 " got=%" PRId64 " ref=%" PRId64 "\n",
                    a, b, got15, ref15);
      ++bad15;
    }
    const int64_t got7 = mul_shift_sat(a, b, kFp7Shift);
    const int64_t ref7 = ref_shift(a, b, 7);
    if (got7 != ref7) {
      if (bad7 < 4)
        std::printf("        [ 7] a=%" PRId64 " b=%" PRId64 " got=%" PRId64 " ref=%" PRId64 "\n",
                    a, b, got7, ref7);
      ++bad7;
    }
  }
  expect(bad15 == 0, "mul_shift_sat(...,15) 随机 20 万组 == 手算参考");
  expect(bad7 == 0, "mul_shift_sat(...,7) 随机 20 万组 == 手算参考");

  // 负数时的向下取整特性（与 cfx 的向零截断差 1 ULP）
  expect(mul_shift_sat(1, 0, 15) == 0, "1.0 * 0.0 == 0");
  // a = -1（表示 -1/2^15），b = 2^15（表示 1.0）-> -1 >> 15 == -1（向下取整）
  expect(mul_shift_sat(-1, 1 << 15, 15) == -1, "负数右移向下取整：-1>>15 == -1");
  expect(cfx::mul(-1, 1) == 0, "对照：cfx 的 -1/100000 向零截断 == 0");
}

// ---------------------------------------------------------------------------
// [5] 其它饱和边界
// ---------------------------------------------------------------------------
void test_saturation_edges() {
  std::printf("[5] 饱和边界\n");

  expect(cfx::mul(INT64_MAX, INT64_MAX) == INT64_MAX, "MAX*MAX 饱和到 MAX");
  expect(cfx::mul(INT64_MIN, INT64_MIN) == INT64_MAX, "MIN*MIN 饱和到 MAX");
  expect(cfx::mul(INT64_MAX, INT64_MIN) == INT64_MIN, "MAX*MIN 饱和到 MIN");
  expect(cfx::mul(0, INT64_MIN) == 0, "0*MIN == 0");
  expect(cfx::add(INT64_MAX, 1) == INT64_MAX, "MAX+1 饱和到 MAX");
  expect(cfx::add(INT64_MIN, -1) == INT64_MIN, "MIN-1 饱和到 MIN");
  expect(cfx::sub(INT64_MIN, 1) == INT64_MIN, "MIN-1（sub）饱和到 MIN");
  expect(mul_sat(1ll << 31, 1ll << 31) == (1ll << 62), "2^31*2^31 == 2^62 精确");
  expect(mul_sat(1ll << 62, 4) == INT64_MAX, "2^62*4 饱和到 MAX");
  expect(cfx::div(INT64_MAX, 1) == INT64_MAX, "div(MAX,1) 饱和到 MAX");
  expect(cfx::div(1, 0) == INT64_MAX, "div(正, 0) -> MAX");
  expect(cfx::div(-1, 0) == INT64_MIN, "div(负, 0) -> MIN");
  expect(cfx::round_to_int_sat(0) == 0, "round(0) == 0");
  expect(cfx::round_to_int_sat(49999) == 0, "round(49999) == 0");
  expect(cfx::round_to_int_sat(50000) == 1, "round(50000) == 1（四舍五入）");
  expect(cfx::round_to_int_sat(-50000) == -1, "round(-50000) == -1");
  expect(cfx::round_to_int_sat(-49999) == 0, "round(-49999) == 0");
  expect(cfx::ssqrt_int_input_guard(0) == 0, "SafeSqrt(0) 不变");
  expect(cfx::ssqrt_int_input_guard(-5) == -5, "SafeSqrt(负) 不变");
  expect(cfx::ssqrt_int_input_guard(INT64_MAX) == INT64_MAX / cfx::kScale,
         "SafeSqrt 把超大输入夹到 INT64_MAX/100000");
  expect(cfx::ssqrt_int_input_guard(92233720368547LL) == 92233720368547LL,
         "SafeSqrt 在阈值上不夹");
}

}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::printf("=== satfix-win 定点饱和算术离线对拍 ===\n");
  std::printf("kScale=%" PRId64 "  kRoundHalf=%" PRId64 "  kSqrtSafeLimit=%" PRId64 "\n\n",
              (int64_t)cfx::kScale, (int64_t)cfx::kRoundHalf, (int64_t)cfx::kSqrtSafeLimit);

  test_int128_layer();
  std::printf("\n");
  test_cfx_mul(500000);
  std::printf("\n");
  test_get_rounded();
  std::printf("\n");
  test_to_fp15();
  std::printf("\n");
  test_fpml();
  std::printf("\n");
  test_saturation_edges();
  std::printf("\n");

  // ---------------------------------------------------------------------------
  // [6] 与游戏内自检跑**同一张向量表**（satfix_decision::selftest_cases）
  //
  //     插件在游戏进程启动时也会跑这张表；这里跑一遍的意义是：
  //     离线就能抓到"期望值写错了"，不用等一次游戏启动。
  // ---------------------------------------------------------------------------
  std::printf("[6] 判定逻辑自检向量表（与游戏内自检同一份数据）\n");
  {
    int failures = satfix_decision::run_selftest(
        nullptr, [](void*, const char* line, bool bad) {
          std::printf("      %s%s\n", line, bad ? "   <== 失败" : "");
        });
    expect(failures == 0, "游戏内自检向量表在离线也全部通过");
  }

  std::printf("\n=== 结果：检查 %d 项，失败 %d 项 -> %s ===\n",
              g_checked, g_fail, g_fail == 0 ? "全部通过" : "有失败");
  return g_fail == 0 ? 0 : 1;
}
