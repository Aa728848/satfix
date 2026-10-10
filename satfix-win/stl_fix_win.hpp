#ifndef SATFIX_STL_FIX_WIN_HPP
#define SATFIX_STL_FIX_WIN_HPP
//
//  stl_fix_win.hpp —— Stellaris 定点类型 <-> 饱和算术，Windows/MSVC 移植版
//
//  与 satfix/stl_fix.hpp 的关系
//  ----------------------------
//  语义**逐条保留**，只是把 GCC 的 `__int128` 与 eirin 依赖换成 satfix128.hpp：
//
//      Linux (stl_fix.hpp)                     Windows (本文件)
//      --------------------------------------  --------------------------------
//      __int128 中间量                          sf128::U128（_umul128/_udiv128）
//      eirin::saturating_*                      sf128::*_sat
//      eirin::fixed_num<...,15>（fpml 方言）     本文件 fpml 部分（见下）
//
//  游戏里有三个定点方言，底层都是 int64：
//
//      CFixedPoint                         十进制, 1.0 = 100000   （战斗/修正/脚本全用它）
//      fpml::fixed_point<long long,48,15>  二进制, 1.0 = 2^15
//      fpml::fixed_point<long long,56,7>   二进制, 1.0 = 2^7
//
//  fpml 那两个在 Linux 侧直接复用了 eirin::fixed_num；Windows 侧不引入 eirin
//  （它依赖自带的 128 位抽象），而是**只实现 satfix 用得到的部分**：
//  算术右移形式的乘法。理由见 fpml 段的注释。
//
//  编码依据（4.5.2 反编译，两侧 build hash 相同：
//            32709cf254181b032b1b309a6ea09776）
//    * CFixedPoint 的乘法内联展开是 (a * b) / 100000，signed 64 位乘 + 向零截断除
//      —— 溢出点在"中间乘积"
//    * CFixedPoint::operator fpml::fixed_point<...>() ：
//        (x % 100000) * 0x40000000 / 0xC3500000 + (x / 100000) * 0x8000
//      其中 0x40000000/0xC3500000 = 2^30/3276800000 = 2^15/10^5，0x8000 = 2^15
//    * 该换算**溢出不了**（fp15 实数上限 2^48 > int64 量程换算出的 9.2e13）
//

#include <cstdint>
#include <cstring>
#include <limits>

#include "satfix128.hpp"

namespace stlfix {

using sf128::add_sat;
using sf128::sub_sat;
using sf128::mul_sat;

// ===========================================================================
// 1) CFixedPoint —— int64, scale = 100000（十进制）
// ===========================================================================
namespace cfx {

inline constexpr int64_t kScale = 100000;
inline constexpr int64_t kOne = 100000;
inline constexpr int64_t kRoundHalf = 50000;             ///< 0.5，GetRounded 用
inline constexpr int64_t kSqrtSafeLimit = 3037000499LL;  ///< x*x 不溢出 int64 的界

inline int64_t add(int64_t a, int64_t b) noexcept { return add_sat(a, b); }
inline int64_t sub(int64_t a, int64_t b) noexcept { return sub_sat(a, b); }

/// @brief 游戏语义的乘法，饱和版：(a * b) / 100000
///
/// 游戏是 `(int64)a * b / 100000`，中间乘积只用 64 位，会 wrap；
/// 这里用 128 位算出真值再饱和回 int64。
inline int64_t mul(int64_t a, int64_t b) noexcept {
  return sf128::mul_div_sat(a, b, (uint64_t)kScale);
}

/// @brief 游戏语义的除法，饱和版：(a * 100000) / b
inline int64_t div(int64_t a, int64_t b) noexcept {
  if (b == 0) return a >= 0 ? INT64_MAX : INT64_MIN;
  return sf128::mul_div_by_sat(a, kScale, b);
}

/// @brief 64 位有符号乘法的低半部分（等价 x86 `imul`），不触发 C++ 溢出 UB。
inline int64_t wrap_mul_i64(int64_t a, int64_t b) noexcept {
  const uint64_t p = (uint64_t)a * (uint64_t)b;
  int64_t ps;
  std::memcpy(&ps, &p, sizeof ps);
  return ps;
}

/// @brief `|x| <= 3037000499`，即 `x*x` 不撑爆 int64。
inline bool fits_i64_square(int64_t x) noexcept {
  return x >= -3037000499LL && x <= 3037000499LL;
}

/// @brief 游戏**实际**的 CFixedPoint 乘法实现（4.5.2 反编译 962757 起）。
///
/// 它有两条路径，不是单纯 `(a*b)/100000`：
///
///   if (|v| <= 3037000499 && |m| <= 3037000499)      // 中间积一定放得下
///       return (v * m) / 100000;
///   else                                             // 拆成 (X/1e5)*Y + (X%1e5)*Y/1e5
///       X = max(v,m), Y = min(v,m)                   // 按**有符号**比较取
///       return ((X % 100000) * Y) / 100000 + (X / 100000) * Y;
///
/// 拆分恒等式本身是**精确**的（trunc(x + n) = trunc(x) + n），所以第二条路径
/// 是等价变形，把溢出边界推到了两个更大的阈值上：
///   * `(X/100000) * Y` 溢出  <=>  |真值| > INT64_MAX  —— 正是该饱和的场合
///   * `(X%100000) * Y` 溢出  <=>  |Y| > ~9.2e13       —— "本可以算对却算错"
///
/// 只用于离线对拍，生产别用。
inline int64_t mul_game(int64_t v, int64_t m) noexcept {
  if (fits_i64_square(v) && fits_i64_square(m)) return wrap_mul_i64(v, m) / kScale;
  const int64_t X = (m < v) ? v : m;
  const int64_t Y = (m <= v) ? m : v;
  return wrap_mul_i64(X % kScale, Y) / kScale + wrap_mul_i64(X / kScale, Y);
}

/// @brief CFixedPoint -> fpml::fixed_point<long long,48,15> 编码
///        （对应 CFixedPoint::operator fpml::fixed_point<...>()）
inline int64_t to_fp15(int64_t x) noexcept {
  // (x % 100000) 最大 99999，乘 0x40000000 后 1e14 量级，64 位放得下；
  // 拆成两段算并饱和，行为与 Linux 版一致。
  const int64_t frac = (x % kScale) * 0x40000000 / 0xC3500000;
  return add_sat(frac, mul_sat(x / kScale, 0x8000));
}

/// @brief 精确饱和版：CFixedPoint -> 整数（四舍五入）
///
/// 游戏实现（反编译 8599412 / 8599430，两个函数体完全一样）：
///   x >= 0 ? (x + 50000) / 100000 : -((50000 - x) / 100000)
/// 两个分支各有一处会溢出：`x + 50000`（x 接近 INT64_MAX）
/// 与 `50000 - x`（x 接近 INT64_MIN）。
inline int64_t round_to_int_sat(int64_t x) noexcept {
  if (x >= 0) return add_sat(x, kRoundHalf) / kScale;
  return -(sub_sat(kRoundHalf, x) / kScale);
}

/// @brief 精确饱和版：CFixedPoint -> fpml::fixed_point<...,15> 编码
///
/// 结论（值得记一笔）：这个换算**溢出不了**。fp15 能表示的实数上限是
/// 2^63 / 2^15 = 2^48 ≈ 2.8e14，而 int64 量程换算成实数上限只有
/// (2^63-1)/1e5 ≈ 9.2e13 < 2^48，所以 `(x/100000)*0x8000` 永远放得下。
/// 保留这个饱和版只是为了把证明写进代码；对应的 hook 实践中不会触发。
inline int64_t to_fp15_sat(int64_t x) noexcept {
  const int64_t frac = (x % kScale) * 0x40000000 / 0xC3500000;
  return add_sat(frac, mul_sat(x / kScale, 0x8000));
}

/// @brief SafeSqrt(long long) 的安全输入域
///
/// 游戏实现（反编译 8599651）：
///   if (p > 0) { local = p * 100000; return SafeSqrt(&local); } return 0;
/// `p * 100000` 在 p > 92233720368547 时溢出。
inline int64_t ssqrt_int_input_guard(int64_t p) noexcept {
  return (p > 0 && p > INT64_MAX / kScale) ? INT64_MAX / kScale : p;
}

}  // namespace cfx

// ===========================================================================
// 2) fpml 方言 —— 二进制，乘法是算术右移（向下取整）
//
//    Linux 侧用 eirin::fixed_num<int64_t, __int128, N, false>，编码与
//    fpml::fixed_point<long long, 48|56, N> 完全一致。
//
//    Windows 侧**不引入 eirin**：eirin 内部依赖它自己的 128 位抽象。satfix 在
//    这两个方言上只用到「饱和乘法」与「编码一致」两件事，所以这里只实现这两件，
//    并用离线对拍证明结果与 Linux 版逐位一致（test_stl_fix_win.cpp 第 4、5 节）。
// ===========================================================================

/// fpml::fixed_point<long long, 48, 15> 的移位量
inline constexpr unsigned kFp15Shift = 15;
/// fpml::fixed_point<long long, 56, 7> 的移位量
inline constexpr unsigned kFp7Shift = 7;

/// @brief 二进制方言的乘法，饱和版：(a * b) >> shift（算术右移 = 向下取整）
///
/// 注意与 cfx::mul 的舍入差异：CFixedPoint 用 `/100000`（向零截断），
/// fpml 用 `>>N`（向下取整），负数时两者会差 1 ULP。
inline int64_t mul_shift_sat(int64_t a, int64_t b, unsigned shift) noexcept {
  return sf128::mul_sar_sat(a, b, shift);
}

}  // namespace stlfix

#endif  // SATFIX_STL_FIX_WIN_HPP
