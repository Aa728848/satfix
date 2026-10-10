#ifndef SATFIX128_HPP
#define SATFIX128_HPP
//
//  satfix128.hpp —— MSVC 上的 128 位中间量算术（Linux 侧由 eirin::fixed_num 提供）
//
//  为什么需要这一层
//  ----------------
//  satfix 的饱和判定必须在 **128 位中间量**上做：游戏溢出正是因为中间乘积只用
//  64 位。Linux 侧用 GCC 的 `__int128`，MSVC 没有这个类型。
//
//  为什么不用 `std::_Signed128`
//  ----------------------------
//  MSVC 的 STL 自带 `_Signed128`（`<__msvc_int128.hpp>`），实测可用，但那是
//  **未文档化的内部头**，随工具链更新可能消失或改形状。所以这里只依赖
//  `<intrin.h>` 里**有文档且长期稳定**的四个内建：
//
//      _umul128(a, b, &hi)      无符号 64x64 -> 128
//      _mul128(a, b, &hi)       有符号 64x64 -> 128（返回低 64 位）
//      _udiv128(hi, lo, d, &r)  无符号 128/64（要求 hi < d，否则 #DE）
//      _udiv128 的配套用法见 udiv128by64
//
//  设计取舍
//  --------
//  不实现通用的 128 位类型（算术、比较、I/O 全套），只实现 satfix 真正需要的三个
//  有饱和语义的运算 + 一个算术右移。API 面越小，越容易用穷举/随机对拍证明正确
//  （见 test/test_stl_fix_win.cpp 与 tools/verify_stlfix_win.py）。
//
//  所有函数都**不触发有符号溢出 UB**：负数一律取幅值后用无符号算，最后再定号。
//

#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <limits>

namespace sf128 {

struct U128 {
  uint64_t hi = 0;
  uint64_t lo = 0;
};

// ---------------------------------------------------------------------------
// 基础：64x64 -> 128 / 128/64 / 比较 / 移位
// ---------------------------------------------------------------------------

inline U128 umul64(uint64_t a, uint64_t b) {
  U128 r;
  r.lo = _umul128(a, b, &r.hi);
  return r;
}

inline bool is_zero(U128 v) { return v.hi == 0 && v.lo == 0; }

inline int ucmp(U128 a, U128 b) {
  if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
  if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
  return 0;
}

/// @brief 无符号 128/64 -> 128 商（丢弃余数）。
///
/// 直接 `_udiv128(v.hi, v.lo, d, &r)` 在 `v.hi >= d` 时会触发 #DE（除零错），
/// 而我们的商**经常**超过 64 位（例如 2^126 / 100000），所以必须自己长除：
/// 先用 64 位除出商的高 64 位，再把余数接到低位继续除。
/// 这样每次调用 `_udiv128` 时其 high 参数都严格小于 d，永远安全。
inline U128 udiv128by64(U128 v, uint64_t d) {
  U128 q;
  q.hi = v.hi / d;
  const uint64_t rem_hi = v.hi % d;
  uint64_t rem = 0;
  q.lo = _udiv128(rem_hi, v.lo, d, &rem);
  return q;
}

// ---------------------------------------------------------------------------
// 有符号 128 位（二补码）：hi 按有符号解释，lo 是低 64 位
// ---------------------------------------------------------------------------

inline U128 negate(U128 v) {
  U128 r;
  r.lo = ~v.lo + 1;
  r.hi = ~v.hi + (r.lo == 0 ? 1 : 0);
  return r;
}

/// @brief 有符号 64x64 -> 128，返回幅值 + 符号。
inline U128 smul64_mag(int64_t a, int64_t b, bool* neg) {
  const bool na = a < 0;
  const bool nb = b < 0;
  *neg = (na != nb);
  const uint64_t ua = na ? (uint64_t)(-(a + 1)) + 1u : (uint64_t)a;
  const uint64_t ub = nb ? (uint64_t)(-(b + 1)) + 1u : (uint64_t)b;
  return umul64(ua, ub);
}

/// @brief 有符号 128 -> int64，越界则夹到 INT64_MAX / INT64_MIN。
///
/// `hi` 按**有符号**解释（二补码）。不能简单地认为 "hi == ~0ull 就下溢"：
/// `hi == -1, lo == 2^64-1` 表示 **-1**，完全在范围内。
/// 分类讨论（值为 `hi*2^64 + lo`）：
///   * hi >= 0：hi == 0 时值 = lo（看是否 <= INT64_MAX）；hi > 0 时恒上溢
///   * hi == -1：值 = lo - 2^64 ∈ [-2^64, -1]，
///       lo < 2^63 时低于 INT64_MIN；否则 = -(2^64 - lo)
///   * hi <= -2：值 <= -2^65 + 2^64 < INT64_MIN，恒下溢
inline int64_t saturate(U128 v) {
  const int64_t hi_s = (int64_t)v.hi;
  if (hi_s >= 0) {
    if (v.hi != 0) return INT64_MAX;
    return v.lo <= (uint64_t)INT64_MAX ? (int64_t)v.lo : INT64_MAX;
  }
  if (hi_s < -1) return INT64_MIN;
  // hi == -1：value = lo - 2^64
  if (v.lo < 0x8000000000000000ull) return INT64_MIN;  // 比 INT64_MIN 还小
  const uint64_t d = 0ull - v.lo;                      // 2^64 - lo ∈ [1, 2^63]
  if (d == 0x8000000000000000ull) return INT64_MIN;    // lo == 2^63 -> -2^63
  return -(int64_t)d;
}

/// @brief 有符号 128 位算术右移（向下取整），然后饱和到 int64。
inline int64_t sar_saturate(U128 v, unsigned n) {
  if (n >= 128) {
    const bool neg = ((int64_t)v.hi) < 0;
    return neg ? -1 : 0;
  }
  U128 r;
  if (n == 0) {
    r = v;
  } else if (n >= 64) {
    const int64_t sh = (int64_t)v.hi >> (n - 64);
    r.lo = (uint64_t)sh;
    r.hi = ((int64_t)v.hi) < 0 ? ~0ull : 0ull;
  } else {
    r.lo = (v.lo >> n) | (v.hi << (64 - n));
    r.hi = ((int64_t)v.hi) >> n;  // 算术右移，MSVC 对 int64_t 是符号扩展
  }
  return saturate(r);
}

/// @brief 有符号除法 + 饱和：saturate(±(mag / d))，d > 0。
inline int64_t div_mag_saturate(U128 mag, uint64_t d, bool neg) {
  const U128 q = udiv128by64(mag, d);
  if (!neg) {
    if (q.hi != 0 || q.lo > (uint64_t)INT64_MAX) return INT64_MAX;
    return (int64_t)q.lo;
  }
  if (q.hi != 0 || q.lo > 0x8000000000000000ull) return INT64_MIN;
  if (q.lo == 0x8000000000000000ull) return INT64_MIN;
  return -(int64_t)q.lo;
}

// ---------------------------------------------------------------------------
// satfix 真正需要的三个运算
// ---------------------------------------------------------------------------

/// @brief saturate((a * b) / d)，d > 0，除法向零截断（与 C++ 整数除法一致）。
inline int64_t mul_div_sat(int64_t a, int64_t b, uint64_t d) {
  bool neg = false;
  const U128 mag = smul64_mag(a, b, &neg);
  return div_mag_saturate(mag, d, neg);
}

/// @brief saturate((a * m) / b)，b 任意（含 0 与负数）。b == 0 时按符号饱和。
inline int64_t mul_div_by_sat(int64_t a, int64_t m, int64_t b) {
  if (b == 0) return (a ^ m) < 0 ? INT64_MIN : INT64_MAX;
  bool neg = false;
  const U128 mag = smul64_mag(a, m, &neg);
  if (b < 0) neg = !neg;
  const uint64_t ub = b < 0 ? (uint64_t)(-(b + 1)) + 1u : (uint64_t)b;
  return div_mag_saturate(mag, ub, neg);
}

/// @brief saturate((a * b) >> n)，算术右移（向下取整）。
inline int64_t mul_sar_sat(int64_t a, int64_t b, unsigned n) {
  bool neg = false;
  U128 mag = smul64_mag(a, b, &neg);
  if (neg) mag = negate(mag);
  return sar_saturate(mag, n);
}

// ---------------------------------------------------------------------------
// 64 位饱和加减（GetRounded / RoundTo 用）
// ---------------------------------------------------------------------------

inline int64_t add_sat(int64_t a, int64_t b) {
  const int64_t r = (int64_t)((uint64_t)a + (uint64_t)b);
  // 同号操作数结果异号 => 溢出
  if (b > 0 && r < a) return INT64_MAX;
  if (b < 0 && r > a) return INT64_MIN;
  return r;
}

inline int64_t sub_sat(int64_t a, int64_t b) {
  const int64_t r = (int64_t)((uint64_t)a - (uint64_t)b);
  if (b < 0 && r < a) return INT64_MAX;
  if (b > 0 && r > a) return INT64_MIN;
  return r;
}

inline int64_t mul_sat(int64_t a, int64_t b) {
  bool neg = false;
  const U128 mag = smul64_mag(a, b, &neg);
  if (neg) {
    if (mag.hi != 0 || mag.lo > 0x8000000000000000ull) return INT64_MIN;
    if (mag.lo == 0x8000000000000000ull) return INT64_MIN;
    return -(int64_t)mag.lo;
  }
  if (mag.hi != 0 || mag.lo > (uint64_t)INT64_MAX) return INT64_MAX;
  return (int64_t)mag.lo;
}

}  // namespace sf128

#endif  // SATFIX128_HPP
