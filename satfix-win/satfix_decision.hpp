#ifndef SATFIX_DECISION_HPP
#define SATFIX_DECISION_HPP
//
//  satfix_decision.hpp —— "这次算错了没有" 的判定逻辑，独立于 hook 机制
//
//  为什么要把这段抽出来
//  --------------------
//  一开始判定逻辑是内联在 detour 里的：读指针 -> 算饱和值 -> 和游戏返回值比。
//  这样它**只能**在游戏真的调用到那个函数时才被走到，而实机能不能走到取决于
//  玩家有没有读档进局 —— 测试成本高、覆盖不住边界。
//
//  抽出来之后：
//
//    * 判定逻辑是纯函数（不碰指针、不碰 hook），可以在离线对拍里用任意输入验证，
//      包括那些正常游戏**永远不会**出现的极值；
//    * detour 只负责"拿到游戏的返回值"，判定交给这里，两边不再各写一份；
//    * 可以带一张**自检向量表**（selftest），在游戏进程里启动时跑一遍 ——
//      于是"逻辑对不对"能在真实进程里留下证据，不必依赖读档。
//
//  一个必须说清的事实
//  ------------------
//  原版量级离溢出阈值极远（`GetRounded` 要 x > 9.2e17 才会分歧），所以
//  **正常游戏过程中几乎不会产生 EVENT**。这正是 Linux README 第 7 节说的
//  "一条 EVENT 都没有 → 到此为止，别开 replace"。
//  因此实机验证能证明的是：
//    (a) 钩子被调用、参数读对、蹦床调用链没坏  —— 靠「首次调用」与自检；
//    (b) 判定逻辑与饱和参考值正确              —— 靠下面的自检向量表；
//  而不是"原版游戏里真的发生过溢出"。
//

#include <cstdint>
#include <cstring>

#include "stl_fix_win.hpp"

namespace satfix_decision {

// ===========================================================================
// 1. 游戏算错的**模型**
//
//    只用于离线对拍与进程内自检 —— 生产路径用的是**真实调用**的返回值，
//    不是这里的模型。模型的作用是让我们能预测"这一组输入该不该分歧"。
// ===========================================================================

/// @brief 游戏 `CFixedPoint::GetRounded()` 的模型（含 wrap 语义）。
///
/// `x + 50000` / `50000 - x` 是有符号 64 位加，越界就 wrap —— 这正是 bug 本身。
/// 所以模型必须照做 wrap；用无符号"修正"它反而复现不出那次已验证的溢出。
inline int64_t model_game_get_rounded(int64_t x) noexcept {
    if (x < 0) {
        const int64_t t = static_cast<int64_t>(50000u - static_cast<uint64_t>(x));
        return -(t / stlfix::cfx::kScale);
    }
    const int64_t t = static_cast<int64_t>(static_cast<uint64_t>(x) + 50000u);
    return t / stlfix::cfx::kScale;
}

/// @brief 游戏 CFixedPoint -> fpml<...,15> 换算的模型。
inline int64_t model_game_to_fp15(int64_t x) noexcept {
    const int64_t frac =
        static_cast<int64_t>(static_cast<uint64_t>(x % 100000) * 0x40000000ull) / 0xC3500000;
    const int64_t whole =
        static_cast<int64_t>(static_cast<uint64_t>(x / 100000) * 0x8000ull);
    return static_cast<int64_t>(static_cast<uint64_t>(frac) + static_cast<uint64_t>(whole));
}

// ===========================================================================
// 2. 判定
// ===========================================================================

struct Check {
    int64_t input = 0;    ///< 喂给游戏的值（或 fp15 原始位模式）
    int64_t game = 0;     ///< 游戏给出的结果
    int64_t sat = 0;      ///< 饱和参考结果
    bool diverges = false;///< 两者是否不同 = 游戏这次算错了
};

inline Check check_get_rounded(int64_t x, int64_t game) noexcept {
    const int64_t sat = stlfix::cfx::round_to_int_sat(x);
    return Check{x, game, sat, game != sat};
}

inline Check check_to_fp15(int64_t x, int64_t game) noexcept {
    const int64_t sat = stlfix::cfx::to_fp15_sat(x);
    return Check{x, game, sat, game != sat};
}

// ===========================================================================
// 3. 进程内自检向量表
//
//    每组都写明"游戏该给什么、饱和该给什么、该不该分歧"。
//    离线对拍（test_stl_fix_win.cpp 第 6 节）与游戏内自检跑的是同一张表，
//    任何一边对不上都会报出来。
// ===========================================================================

struct SelfCase {
    const char* key;       ///< "GetRounded" / "to_fp15"
    const char* note;
    int64_t     input;
    int64_t     expect_game;
    int64_t     expect_sat;
    bool        expect_diverge;
};

// GetRounded 的溢出界：`x + 50000 > INT64_MAX` <=> `x > INT64_MAX - 50000`
//                       即 x >= 9223372036854725808
// 下面两个常量与表中的期望值都是**从实现里实跑出来的**，不是手算的
// （手算最容易在这里差一，_probe 跑过一遍才写进表）。
inline constexpr int64_t kRoundUpperEdge = 9223372036854725807LL;  ///< 最后一个不溢出
inline constexpr int64_t kRoundFirstBad = 9223372036854725808LL;   ///< 第一个溢出

inline const SelfCase* selftest_cases(int* count) noexcept {
    static const SelfCase kCases[] = {
        // ---- 常规值：不该分歧 ----
        {"GetRounded", "零", 0, 0, 0, false},
        {"GetRounded", "常规正数（四舍五入）", 123456, 1, 1, false},
        {"GetRounded", "常规负数", -123456, -1, -1, false},
        {"GetRounded", "半值进位", 50000, 1, 1, false},
        {"GetRounded", "半值不进位", 49999, 0, 0, false},

        // ---- 上界：最后安全值 / 第一个坏值（正好卡在边界上）----
        {"GetRounded", "上界最后一个安全值", kRoundUpperEdge, 92233720368547LL, 92233720368547LL,
         false},
        {"GetRounded", "上界第一个溢出值 x+50000 wrap", kRoundFirstBad, -92233720368547LL,
         92233720368547LL, true},
        {"GetRounded", "INT64_MAX（已实测复现）", INT64_MAX, -92233720368547LL, 92233720368547LL,
         true},

        // ---- 下界：`50000 - x` wrap ----
        {"GetRounded", "INT64_MIN（已实测复现）", INT64_MIN, 92233720368547LL, -92233720368547LL,
         true},

        // ---- to_fp15：Linux 侧已证明该换算溢出不了，预期全部分歧=false ----
        {"to_fp15", "零", 0, 0, 0, false},
        {"to_fp15", "常规正数", 123456, 40454, 40454, false},
        {"to_fp15", "常规负数", -123456, -40454, -40454, false},
        {"to_fp15", "INT64_MAX", INT64_MAX, 3022314549036572936LL, 3022314549036572936LL, false},
        {"to_fp15", "INT64_MIN", INT64_MIN, -3022314549036572936LL, -3022314549036572936LL, false},
    };
    *count = static_cast<int>(sizeof(kCases) / sizeof(kCases[0]));
    return kCases;
}

/// @brief 跑一遍自检表，返回失败条数；每条结果通过 `sink` 报告。
///
/// `sink(user, line, is_failure)` —— 由调用方决定写日志还是打 stdout。
template <class Sink>
inline int run_selftest(void* user, Sink sink) noexcept {
    int n = 0;
    const SelfCase* cases = selftest_cases(&n);
    int failures = 0;
    char buf[320];

    for (int i = 0; i < n; ++i) {
        const SelfCase& c = cases[i];
        // 用模型预测游戏结果，再用判定函数算饱和值与分歧
        const int64_t model = (std::strcmp(c.key, "GetRounded") == 0)
                                  ? model_game_get_rounded(c.input)
                                  : model_game_to_fp15(c.input);
        const Check chk = (std::strcmp(c.key, "GetRounded") == 0)
                              ? check_get_rounded(c.input, model)
                              : check_to_fp15(c.input, model);

        const bool model_ok = (model == c.expect_game);
        const bool sat_ok = (chk.sat == c.expect_sat);
        const bool div_ok = (chk.diverges == c.expect_diverge);
        const bool pass = model_ok && sat_ok && div_ok;
        if (!pass) ++failures;

        std::snprintf(buf, sizeof buf, "%s %s: in=%lld model=%lld(exp %lld) sat=%lld(exp %lld) %s",
                      pass ? "PASS" : "FAIL", c.note, (long long)c.input, (long long)model,
                      (long long)c.expect_game, (long long)chk.sat, (long long)c.expect_sat,
                      chk.diverges ? "分歧" : "一致");
        sink(user, buf, !pass);
    }
    std::snprintf(buf, sizeof buf, "自检合计 %d 组，失败 %d 组", n, failures);
    sink(user, buf, failures != 0);
    return failures;
}

}  // namespace satfix_decision

#endif  // SATFIX_DECISION_HPP
