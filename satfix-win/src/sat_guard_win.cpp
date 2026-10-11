//
//  sat_guard_win.cpp —— satfix 的 Windows 插件（Stellaris Launcher DLL 插件）
//
//  这是 satfix（Linux 的 LD_PRELOAD 定点算术饱和注入）在 Windows 上的对应物。
//  合规要求全部对照 `stellaris-launcher/docs/PLUGIN_HANDBOOK.zh-CN.md`：
//
//    6.1  DllMain 极简：只 CreateThread，不等待/不加载库/不做文件与网络
//    6.2  插件文件夹从**自己模块的地址**取，不用工作目录、不写死 Documents
//    6.3  引擎函数只在游戏主线程调用 -> 见「主线程泵」小节
//    6.4  原始内存读取用 SEH（winhook::safe_read），坏指针不崩游戏
//    6.5  detour 必须调原函数、不恢复他人钩子（winhook 的 call()）
//    6.6  不卸载自己：不调用 FreeLibraryAndExitThread
//    6.7  静态链接运行库（/MT）、不弹控制台、只支持 x64
//    8    从 <插件文件夹>\config\ 读设置、缺失时用内置默认值、支持热重载
//    9    日志写 <插件文件夹>\logs\，用 _SH_DENYWR 允许游戏运行时读取
//    4/7  清单里列 exe_timestamps，DLL 自己也校验 PE 时间戳与序言签名
//
//  两种构建模式（编译期开关，见 build.ps1）：
//    -Replace  -> 回写模式：检出溢出就把值改成饱和值。**发布版用这个**。
//    不加参数  -> 影子模式：只观测、只打日志，不改游戏数值。开发自测用。
//  模式会打进二进制（kBuildMode 那个 marker），日志第一行也会写出来，
//  所以拿到一个 dll 能当场验出是哪种，不用靠记性。
//
//  覆盖范围：src/satfix_targets_win.generated.hpp 里已确证的目标。
//  未定位的目标会在启动日志里逐条列出 —— 不假装支持。
//
//  ── 关于线程（手册 6.3，最容易让游戏静默崩溃的地方）────────────────────
//  本插件**不**从自有线程调用任何引擎函数。被 hook 的函数本身运行在游戏主线程，
//  所以 detour 里的读参数/算影子/写回值是安全的。detour 只做「纯算术 + 记数」，
//  真正的活（日志格式化、配置热重载、统计汇总）都排到 g_tasks，由
//  「主线程泵」在**下一次游戏主线程进入任一被 hook 函数时**执行。
//  这样既不需要 hook Present/DXGI，也不会从别的线程碰引擎状态。
//

#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <share.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>

#include "winhook.hpp"
#include "stl_fix_win.hpp"
#include "satfix_decision.hpp"
#include "satfix_targets_win.generated.hpp"

#ifndef SATFIX_REPLACE
#define SATFIX_REPLACE 0
#endif

/// 构建模式标记：**打进二进制**，便于用字节搜索当场确认某个 DLL 是哪种模式。
///
/// 为什么要这个：发布过一次「以为是影子版、其实是回写版」的包 ——
/// 两种构建的 DLL 大小完全相同（323072 B），只看大小/时间分不出来，
/// 只能靠记性，而记性错了。有这个 marker 就能一条命令验出来。
/// tools/package_release.ps1 会读它并在打包时报告模式。
// 用 const char*（不是数组）：三目两个分支的字面量长度不同，
// 声明成数组会报 C2440「无法从 const char* 转换为 const char[]」。
const char* const kBuildMode =
    SATFIX_REPLACE ? "satfix-build-mode:write-back" : "satfix-build-mode:shadow";

#ifndef SATFIX_MAX_LOGS
// 500 行在开心跳时会不够用（实测：20000 次调用一块，几十秒就写满）。
// 提到 4000：既能容纳一整局的心跳，也不会让日志无限增长。
#define SATFIX_MAX_LOGS 20000
#endif

namespace {

using namespace stlfix;
using namespace satfix_win;

// ===========================================================================
// 插件目录（手册 6.2）
// ===========================================================================

/// 从**本模块地址**取 DLL 路径，其父目录就是插件文件夹。
/// 手册 6.2：绝不用当前工作目录（那是游戏目录），也不写死 Documents 路径。
const std::wstring& plugin_dir() {
    static const std::wstring dir = []() -> std::wstring {
        HMODULE self = nullptr;
        wchar_t path[MAX_PATH * 4] = {};
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&plugin_dir), &self);
        GetModuleFileNameW(self, path, static_cast<DWORD>(std::size(path)));
        std::wstring p(path);
        const size_t slash = p.find_last_of(L"\\/");
        return slash == std::wstring::npos ? std::wstring() : p.substr(0, slash + 1);
    }();
    return dir;
}

// ===========================================================================
// 日志（手册 9.1）
// ===========================================================================

FILE* g_log = nullptr;
std::atomic<uint64_t> g_log_lines{0};
std::atomic<uint64_t> g_log_dropped{0};

/// 拼行缓冲与写锁。detour 跑在多个游戏线程上，见 log_line_raw 的说明。
SRWLOCK g_log_lock = SRWLOCK_INIT;
char g_log_buf[2048];

void log_line_raw(const char* line) {
    if (g_log == nullptr) return;

    // 整行（前缀 + 正文 + 换行）先拼进一个缓冲，再**一次** fputs 写出。
    //
    // 为什么要这样：早先这里是三次独立调用（fputs 前缀 / fputs 正文 / fputc 换行），
    // 两个线程会**插在中间**，实机就出现过
    //     CalcDiplomaticWeight  50986[satfix] --- heartbeat: ...
    // 这种断行。拼成一次调用后，CRT 对 FILE 的单次操作自带锁，行与行不会再交错。
    static const char kPrefix[] = "[satfix] ";
    constexpr size_t kPrefixLen = sizeof kPrefix - 1;
    const size_t n = std::strlen(line);
    if (n > sizeof g_log_buf - kPrefixLen - 2) return;

    // 计数与写入放进同一把锁，避免两个线程同时越过行数上限、或同时用同一个缓冲。
    AcquireSRWLockExclusive(&g_log_lock);
    if (g_log_lines.load(std::memory_order_relaxed) >= SATFIX_MAX_LOGS) {
        g_log_dropped.fetch_add(1, std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_log_lock);
        return;
    }
    g_log_lines.fetch_add(1, std::memory_order_relaxed);

    std::memcpy(g_log_buf, kPrefix, kPrefixLen);
    std::memcpy(g_log_buf + kPrefixLen, line, n);
    g_log_buf[kPrefixLen + n] = '\n';
    g_log_buf[kPrefixLen + n + 1] = '\0';
    std::fputs(g_log_buf, g_log);
    std::fflush(g_log);  // 崩溃时也要留下最后几行
    ReleaseSRWLockExclusive(&g_log_lock);
}

void whk_log(const char* line) { log_line_raw(line); }

void logf(const char* fmt, ...) {
    char buf[768];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    log_line_raw(buf);
}

/// 以「可读可写共享」打开日志（手册 9.1 的意图）。
///
/// 手册建议 `_wfsopen(..., _SH_DENYWR)`。实测在一个 EXE 里 LoadLibrary 后，
/// `_wfopen_s`（以及本次实测的 `_SH_DENYWR`）会返回 EACCES，而 Win32 层
/// `CreateFileW(GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE)` 能正常读 ——
/// 说明 CRT 的共享标志映射在 Win32 上不等价于「允许读者」。
/// 所以这里直接用 `_wopen` 传**显式**的 `_SH_DENYNO`，
/// 语义与实测能力都对得上，并且由 test_load_plugin 的可读性断言守住。
FILE* open_log_file(const std::wstring& path) {
    // _wsopen_s 才能同时指定 oflag 与 shflag；_wopen 的第三个参数是 pmode。
    int fd = -1;
    const errno_t rc = _wsopen_s(&fd, path.c_str(),
                                 _O_WRONLY | _O_CREAT | _O_TRUNC | _O_TEXT,
                                 _SH_DENYNO, _S_IREAD | _S_IWRITE);
    if (rc != 0 || fd < 0) return nullptr;
    // _fdopen 之后由 FILE* 接管，写日志时再显式 fflush
    return _fdopen(fd, "w");
}

// ===========================================================================
// 配置（手册 8）：<插件文件夹>\config\satfix.ini
// ===========================================================================

struct Settings {
    bool     enabled = true;            ///< false = 只装钩子不记事件（几乎没用，留作开关）
    bool     heartbeat = false;         ///< 周期性汇总
    uint64_t heartbeat_every = 200000;
    bool     verbose_events = true;     ///< 打印每条 EVENT
    /// 护盾/装甲/船体上限的「荒谬上限」，单位是 CFixedPoint 存储值（1e5 = 1 游戏单位）。
    ///
    /// **实测教训**：原本设 1e11（= 100 万游戏单位），结果在装了 mod 的存档里刷出
    /// 3927 条假 EVENT —— mod 的护盾正常就有 100 亿（1e10）游戏单位，远超那个阈值。
    /// 阈值定低了不是「多报几条」，是**把真问题淹掉**。
    ///
    /// 现在默认 1e18 存储值（= 1e13 游戏单位），已经贴近 int64 上限（9.22e18 存储值），
    /// 所以实际上**只靠 v < 0 那条判据**：int64 的正数乘法溢出必然 wrap 成负数，
    /// 而「大正数」在 mod 存档里是合法的。保留这个上界只是兜住极端荒谬值。
    int64_t  max_hp_cap = 1000000000000000000LL;
    /// 变量系统（var_add / var_multiply）做影子复算：要读回变量当前值，
    /// 依赖 4 个辅助函数的 RVA 解析成功。解析不到时自动退化成只计数。
    /// 这是 EXACT 路径，比其它目标多几次间接调用，出问题可以一键关掉。
    bool     verify_variables = true;
    /// 护盾/装甲/船体上限做忠实重算（等值比对 + 溢出回写饱和值）。
    /// 依赖 ship_size_of / modifier_value 两个辅助函数解析成功；
    /// 解析不到时自动退化成「只认负数」。同样可以一键关掉。
    bool     verify_max_hp = true;
    /// 把「重算≠游戏但未达回写阈值」也写进日志（诊断用，默认关）。
    /// 实测船体上限会系统性不等（算式里还有一段条件性累加未建模），
    /// 开着会刷满日志；只在排查重算本身时才打开。
    bool     log_recompute_mismatch = false;
    /// 头 N 次上限调用打印重算链每一段的中间量（默认 12，0 = 关）。
    /// 「溢出没被抓到」时用它定位卡在哪一段。
    /// 头 N 次上限调用打印重算链每一段的中间量（0 = 关，**默认关**）。
    /// ⚠️ 开启会让 detour_max_hp 走完整重算（绕过快速路径），有性能代价 ——
    /// 只在排查「为什么没抓到溢出」时短时打开。
    int      diag_recompute_calls = 0;
    /// 统计流经 ApplyModifierMult 的 ModifierType 直方图（0 = 关，**默认关**）。
    /// 开启后每次调用多一次原子加 —— 那条路 463 万次调用，别常态开着。
    int      diag_modifier_calls = 0;
    /// 「加算溢出塌成 0」事件最多写多少行（每条 design 只写一次，见 detour_max_hp）。
    /// 舰船详情面板每帧重算，不限流会一次刷满日志。
    int      collapse_log_limit = 64;
};

std::wstring config_path() { return plugin_dir() + L"config\\satfix.ini"; }

std::string trim(std::string s) {
    const char* ws = " \t\r\n";
    const size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return std::string();
    const size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

bool is_true(const std::string& v) {
    return _stricmp(v.c_str(), "1") == 0 || _stricmp(v.c_str(), "true") == 0 ||
           _stricmp(v.c_str(), "yes") == 0 || _stricmp(v.c_str(), "on") == 0;
}

/// 读 config\satfix.ini。文件不存在时返回内置默认值（手册 8.1）。
Settings read_settings(bool* found) {
    Settings s;
    std::ifstream in(config_path(), std::ios::binary);
    *found = in.is_open();
    std::string line, section;
    bool first = true;
    while (std::getline(in, line)) {
        if (first && line.rfind("\xEF\xBB\xBF", 0) == 0) line.erase(0, 3);  // UTF-8 BOM
        first = false;
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2);
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = trim(line.substr(0, eq));
        const std::string val = trim(line.substr(eq + 1));
        if (_stricmp(section.c_str(), "general") != 0) continue;
        if (key == "enabled") s.enabled = is_true(val);
        else if (key == "heartbeat") s.heartbeat = is_true(val);
        else if (key == "heartbeat_every") s.heartbeat_every = _strtoui64(val.c_str(), nullptr, 10);
        else if (key == "verbose_events") s.verbose_events = is_true(val);
        else if (key == "verify_variables") s.verify_variables = is_true(val);
        else if (key == "verify_max_hp") s.verify_max_hp = is_true(val);
        else if (key == "log_recompute_mismatch") s.log_recompute_mismatch = is_true(val);
        else if (key == "diag_recompute_calls")
            s.diag_recompute_calls = (int)_strtoi64(val.c_str(), nullptr, 10);
        else if (key == "diag_modifier_calls")
            s.diag_modifier_calls = (int)_strtoi64(val.c_str(), nullptr, 10);
        else if (key == "collapse_log_limit")
            s.collapse_log_limit = (int)_strtoi64(val.c_str(), nullptr, 10);
        else if (key == "max_hp_cap") {
            const long long v = _strtoi64(val.c_str(), nullptr, 10);
            if (v > 0) s.max_hp_cap = v;
        }
    }
    if (s.heartbeat_every == 0) s.heartbeat_every = 200000;
    return s;
}

Settings g_settings;
std::atomic<bool> g_reload_requested{false};

FILETIME settings_mtime() {
    WIN32_FILE_ATTRIBUTE_DATA d{};
    return GetFileAttributesExW(config_path().c_str(), GetFileExInfoStandard, &d)
               ? d.ftLastWriteTime
               : FILETIME{};
}

// ===========================================================================
// 统计与「主线程泵」
// ===========================================================================

std::atomic<uint64_t> g_calls{0};
std::atomic<uint64_t> g_events{0};
std::atomic<uint64_t> g_replaced{0};

enum : int {
    kIdxGetRounded = 0,
    kIdxToFp15,
    kIdxApplyMul,
    kIdxApplyMulFp15,
    kIdxVarMultiply,
    kIdxGetRoundedFp15,
    kIdxRoundTo,
    kIdxAtan2,
    kIdxShieldMax,
    kIdxArmorMax,
    kIdxHullMax,
    kIdxVarAdd,
    kIdxSqrt,
    kIdxSafeSqrt,
    kIdxDiploWeight,
    kIdxMpe15,
    kIdxMpe7,
    kIdxDamagePerDay,
    kIdxCount
};

// kIdx* 是**计数/报告**用的下标，与 kTargets[] 的顺序无关：安装走的是 t.key 字符串匹配，
// 每个 detour 内部用自己那个 kIdx 常量，所以两边不会串。
// 这里只钉住「下标个数 == 目标个数」，防止加了目标忘了加计数器。
static_assert(kTargetCount == 18, "kIdx* 下标个数需要跟着 kTargets 更新");
const char* const kIdxNames[kIdxCount] = {
    "GetRounded/GetRounded64",
    "operator fpml::fixed_point<...,15>",
    "ApplyModifierMult(cfx)",
    "ApplyModifierMult(fp15)",
    "multiply_variable",
    "GetRounded(fp15)",
    "RoundTo",
    "Atan2",
    "CalcMaxShieldHitPoints",
    "CalcMaxArmorHitPoints",
    "CalcMaxHitPoints",
    "add_variable",
    "Sqrt",
    "SafeSqrt",
    "CalcDiplomaticWeight",
    "CalcMilitaryPowerExponent<15>",
    "CalcMilitaryPowerExponent<7>",
    "CalcAverageDamagePerDay",
};
std::atomic<uint64_t> g_fn_calls[kIdxCount];
bool g_fn_seen[kIdxCount] = {false, false, false, false, false, false, false, false,
                             false, false, false, false, false, false, false, false,
                             false, false};

/// 主线程泵：只在游戏主线程进入被 hook 函数时被调用。
/// detour 里只做原子写，把重活推迟到这里 —— 满足手册 6.3。
void game_thread_pump() {
    if (g_reload_requested.exchange(false)) {
        bool found = false;
        g_settings = read_settings(&found);
        logf("设置已重载（%s）", found ? "config\\satfix.ini" : "文件缺失，用内置默认值");
    }
}

int next_idx() {
    static std::atomic<int> n{0};
    return n.fetch_add(1, std::memory_order_relaxed);
}

void note_first_call(int idx) {
    if (!g_fn_seen[idx]) {
        g_fn_seen[idx] = true;
        // 首次调用心跳（有界输出：每个目标最多 1 行）
        logf("首次调用: %s", kIdxNames[idx]);
    }
}

/// @brief 周期汇总。
///
/// **必须拼成一整块再写**：detour 运行在游戏的主线程/渲染线程/worker 上，
/// 心跳是并发触发的。早先的实现逐行 logf，实测输出会互相穿插成
/// `--- heartbeat: 3020000 ... ---[satfix]  ApplyModifierMult(cfx) 1382087`，
/// 统计就没法读了。这里先在栈上拼好整块，再一次性落盘。
void maybe_heartbeat(uint64_t total) {
    if (!g_settings.heartbeat) return;
    const uint64_t every = g_settings.heartbeat_every;
    if (every == 0 || (total % every) != 0) return;

    char buf[1024];
    int off = _snprintf_s(buf, sizeof buf, _TRUNCATE,
                          "--- heartbeat: %llu 次调用，溢出 %llu 次 ---",
                          (unsigned long long)total, (unsigned long long)g_events.load());
    if (off < 0) off = 0;
    for (int i = 0; i < kIdxCount && off < (int)sizeof buf - 80; ++i) {
        const uint64_t n = g_fn_calls[i].load(std::memory_order_relaxed);
        if (n == 0) continue;
        const int w = _snprintf_s(buf + off, sizeof buf - off, _TRUNCATE,
                                  "\n      %-36s %llu", kIdxNames[i], (unsigned long long)n);
        if (w < 0) break;
        off += w;
    }
    log_line_raw(buf);
}

// ===========================================================================
// 目标解析：RVA + 序言签名双重校验（手册 6.4 / 7）
// ===========================================================================

struct Resolved {
    const Target* t = nullptr;
    void* addr = nullptr;
    bool ok = false;
};

/// 先按 RVA 算地址，再逐字节比对序言签名。
/// 签名不匹配（游戏更新过 / 不是这个构建）就返回 false，调用方跳过该目标。
bool verify_signature(void* addr, const uint8_t* sig, size_t n) {
    uint8_t got[SATFIX_WIN_SIG_LEN] = {};
    if (n > SATFIX_WIN_SIG_LEN) return false;
    if (!whk::safe_read(got, addr, n)) return false;
    return std::memcmp(got, sig, n) == 0;
}

int resolve_targets(Resolved* out, int cap) {
    int n = 0;
    for (int i = 0; i < kTargetCount && n < cap; ++i) {
        const Target& t = kTargets[i];
        void* addr = whk::image_base_plus(t.rva);
        if (!whk::is_mapped(reinterpret_cast<uintptr_t>(addr))) {
            logf("跳过 %s：RVA 0x%08x 不在本进程映射里", t.key, t.rva);
            continue;
        }
        if (!verify_signature(addr, t.sig, SATFIX_WIN_SIG_LEN)) {
            logf("跳过 %s：RVA 0x%08x 的序言签名不匹配（游戏可能已更新）", t.key, t.rva);
            continue;
        }
        out[n].t = &t;
        out[n].addr = addr;
        out[n].ok = true;
        ++n;
    }
    return n;
}

// ===========================================================================
// 辅助函数解析（只解析地址 + 签名校验，不装钩子）
//
// 这四个是变量系统 EXACT 的前提：要能在**调用原函数之前**读回变量当前值，
// 才能复算饱和结果并与游戏写回值比对。
// ===========================================================================
namespace {
void* g_helper[kHelperCount] = {};

/// 按 key 取辅助函数地址；没解析到就返回 nullptr（调用方必须退化处理）。
void* helper_addr(const char* key) {
    for (int i = 0; i < kHelperCount; ++i)
        if (std::strcmp(kHelpers[i].key, key) == 0) return g_helper[i];
    return nullptr;
}

int resolve_helpers() {
    int n = 0;
    for (int i = 0; i < kHelperCount; ++i) {
        const Helper& h = kHelpers[i];
        void* addr = whk::image_base_plus(h.rva);
        if (!whk::is_mapped(reinterpret_cast<uintptr_t>(addr))) {
            logf("辅助 %s：RVA 0x%08x 不在本进程映射里", h.key, h.rva);
            continue;
        }
        if (!verify_signature(addr, h.sig, SATFIX_WIN_SIG_LEN)) {
            logf("辅助 %s：RVA 0x%08x 的序言签名不匹配", h.key, h.rva);
            continue;
        }
        g_helper[i] = addr;
        ++n;
    }
    return n;
}
}  // namespace

// ===========================================================================
// detour
//
//  ABI 来自反编译确认（不是猜的）：
//
//  1) CFixedPoint::GetRounded() const          —— 非 sret，返回槽在 rax
//         long long fn(const long long* self)
//      反编译：lVar1 = *param_1; ... return lVar2 / 100000;  （param_1 即 this）
//
//  2) CFixedPoint::operator fpml<...,15>() const —— ABI 由**机器码 + 调用点**确证
//         签名（C++ 参数顺序）：long long* fn(const long long* src, long long* ret)
//      证据一（机器码，0x1B4C0A0 前 6 字节）：
//             4c 8b 01   mov r8, [rcx]   ; 源从 RCX 进来，而且是**解引用**
//             4c 8b d2   mov r10, rdx    ; 返回槽是 RDX，先存进 r10 备用
//          → rcx = src, rdx = ret_slot。所以 C++ 里第一个参数对应 rcx（源）、
//            第二个对应 rdx（返回槽）。
//      证据二（调用点）：`FUN_141b4c0a0(&DAT_1431517c8, local_368)`
//          —— 第一个实参是源地址、第二个是接收结果的局部变量。
//      **踩过的坑**：我一开始按「rdx=源、rcx=返回槽」写，探针四个输入全返回 0，
//      因为 x=0 恒定时它读的是 *(&slot)=0、把结果写进了我的 x。
//      教训：即使机器码摆在那里，也要按**参数顺序**逐一核对，别只看寄存器角色。
//
//  3) CMultiplyVariableEffect::ExecuteActual(CEventScope&) const —— void
//         void fn(const void* self, const void* scope)
//      反编译看到的是 (param_1, param_2, param_3)，其中 param_2 是被就地累加的那个
//      "数组指针"，因为 Ghidra 把 this 与两个实参混在了一起；本目标的策略是
//      OBSERVE，**完全不读参数、不依赖这个签名**，只记「被调用过」与心跳。
//
//  4) CFixedPoint::GetRounded(fpml const&) —— 非 sret，返回槽在 rax，参数是 fp15 位模式
//         long long fn(const long long* fp15_bits)
//      反编译：uVar1 = *param_2; ... 用的是 param_2（不是 this）。
//      本目标是 OBSERVE：只计数，不判罚（Linux 侧同为 OBSERVE）。
//
//  判定逻辑统一走 satfix_decision.hpp，不在 detour 里各写一份。
// ===========================================================================

using FnGetRounded = long long (*)(const long long* self);
// ABI 由机器码 + 调用点确证：rcx = 源（解引用），rdx = 返回槽
// 所以 C++ 参数顺序是 (src, ret)，别写成 (ret, src)。
using FnToFp15     = long long* (*)(const long long* src, long long* ret_slot);
using FnVarMul     = void (*)(const void* self, const void* scope);
using FnGetRoundedFp15 = long long (*)(const long long* fp15_bits);

whk::TypedHook<FnGetRounded> g_hook_get_rounded;

long long detour_get_rounded(const long long* self) {
    const int idx = kIdxGetRounded;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    long long x = 0;
    if (!whk::safe_read(&x, self, sizeof x)) {
        // 读不到就纯透传，绝不让坏指针崩游戏（手册 6.4）
        return g_hook_get_rounded.call(self);
    }

    // 先拿游戏自己的结果，再用共享判定逻辑比
    const int64_t game = g_hook_get_rounded.call(self);
    const satfix_decision::Check chk = satfix_decision::check_get_rounded(x, game);

    if (chk.diverges) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT GetRounded x=%lld game=%lld sat=%lld", (long long)x,
                 (long long)game, (long long)chk.sat);
#if SATFIX_REPLACE
        g_replaced.fetch_add(1, std::memory_order_relaxed);
        return chk.sat;
#endif
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return game;
}

whk::TypedHook<FnToFp15> g_hook_to_fp15;

long long* detour_to_fp15(const long long* src, long long* ret_slot) {
    const int idx = kIdxToFp15;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    long long* const r = g_hook_to_fp15.call(src, ret_slot);

    long long x = 0;
    if (!whk::safe_read(&x, src, sizeof x)) return r;

    const int64_t game = (r != nullptr) ? *r : 0;
    const satfix_decision::Check chk = satfix_decision::check_to_fp15(x, game);

    // 该换算在 Linux 侧已被证明溢出不了；这里作为"证明"保留，
    // 一旦真的触发，说明我们对量程的推导有误，必须记下来。
    if (chk.diverges) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT to_fp15 x=%lld game=%lld sat=%lld  <== 预期不会发生", (long long)x,
                 (long long)game, (long long)chk.sat);
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

// ===========================================================================
// 变量系统（var_add / var_multiply）—— 真正的 EXACT
//
//  ABI 全部由反编译确证（不是猜的）：
//      AccessVariablePointer(scope, name)          -> CVariables*      [0x9F7DF0]
//      GetVariable(vars+8, out, name)              -> out[0] = 条目     [0x227390]
//      SetVariable(vars, name, value)              -> void             [0x7AAE10]
//      GetValue(this+0xf0, out, scope)             -> out[0] = CFixedPoint [0x34D500]
//
//  变量值的存放位置：**条目 + 0x38**（cvars_get 的读偏移与 cvars_set 的写偏移
//  在反编译里互为印证）。条目 +4 是「已设」标志：== -1 表示未设，此时游戏
//  按 0 参与运算 —— 我们的影子读法必须**照抄这个分支**，否则会读到未初始化槽。
//
//  为什么这两个现在能做 EXACT（上一轮还只能 OBSERVE）：
//  上一轮卡在「读不回 v0」。这一轮从已确证的 var_multiply 调用点把这四个
//  辅助函数的 RVA 读出来了，读回路径就通了：
//      1. 调原函数**之前**读出 v0（条目 +0x38，未设则 0）
//      2. 读出本效果的操作数 d（GetValue）
//      3. 调原函数，让它正常写回
//      4. 读回 v1，与 cfx::add / cfx::mul 的饱和结果比对
//  REPLACE=1 时第 4 步用 SetVariable 把饱和值写回去。
// ===========================================================================
using FnAccessVarPtr = long long (*)(const void* scope, const void* name);
using FnGetVariable  = long long* (*)(const void* vars8, long long* out, const void* name);
using FnSetVariable  = void (*)(const void* vars, const void* name, long long value);
using FnGetValue     = long long* (*)(const void* this_f0, long long* out, const void* scope);

whk::TypedHook<FnVarMul> g_hook_var_mul;
whk::TypedHook<FnVarMul> g_hook_var_add;

/// 变量的「名字 CString」在效果对象里的偏移：Linux 是 +0xb8，MSVC 布局 +0xc0。
constexpr size_t kVarNameOff = 0xc0;
/// CFixedPointVariableValue 值成员：Linux +0xe8，MSVC +0xf0。
constexpr size_t kVarValueOff = 0xf0;
/// 变量条目里 CFixedPoint 值的偏移。
constexpr size_t kEntryValueOff = 0x38;

/// 照抄游戏的「读变量当前值」：未设（条目 +4 == -1）按 0 处理。
bool var_read_v0(const void* self, const void* scope, long long* v0_out) {
    auto access = reinterpret_cast<FnAccessVarPtr>(helper_addr("access_var_pointer"));
    auto getvar = reinterpret_cast<FnGetVariable>(helper_addr("cvars_get"));
    if (access == nullptr || getvar == nullptr) return false;

    const char* name = static_cast<const char*>(self) + kVarNameOff;
    const long long vars = access(scope, name);
    if (vars == 0) return false;

    long long entry = 0;
    getvar(reinterpret_cast<const void*>(vars + 8), &entry, name);
    if (entry == 0) return false;

    // 与游戏同构：*(char*)(entry+4) == -1 表示未设，按 0 参与运算
    *v0_out = (*reinterpret_cast<const signed char*>(entry + 4) == -1)
                  ? 0
                  : *reinterpret_cast<const long long*>(entry + kEntryValueOff);
    return true;
}

/// 调原函数**之后**读回写进条目的值（同样照抄未设分支）。
bool var_read_v1(const void* self, const void* scope, long long* v1_out) {
    return var_read_v0(self, scope, v1_out);
}

/// 读本效果的操作数 d = CFixedPointVariableValue::GetValue(self+0xf0, scope)。
bool var_read_operand(const void* self, const void* scope, long long* d_out) {
    auto getvalue = reinterpret_cast<FnGetValue>(helper_addr("cfp_getvalue"));
    if (getvalue == nullptr) return false;
    long long out = 0;
    getvalue(static_cast<const char*>(self) + kVarValueOff, &out, scope);
    *d_out = out;
    return true;
}

/// 变量系统的影子复算 + 回写。
///
/// `op` 取 "add" 或 "mul"。调原函数拿到游戏写回的值 v1，与饱和值 sat 比对：
/// 不一致就是游戏 wrap 了，记一条 EVENT；回写模式下再用 SetVariable 把 sat 写回去。
///
/// 前 kSampleLog 次调用会无条件打印 (v0, d, v1, sat) 四元组：
/// 「0 条 EVENT」既可能是真的一致，也可能是影子读到的值根本没意义。
/// 只有把读到的三元组打出来、看着它满足 `v1 == v0 op d`，才能证明这条读回链是通的。
/// 有界输出（每个操作最多 3 行），不会刷日志。
void shadow_variable(const char* name, const char* op, const void* self, const void* scope,
                     whk::TypedHook<FnVarMul>& hk) {
    long long v0 = 0, d = 0;
    const bool can_read = var_read_v0(self, scope, &v0) && var_read_operand(self, scope, &d);
    hk.call(self, scope);  // 让游戏照常写回
    if (!can_read) return;

    long long v1 = 0;
    if (!var_read_v1(self, scope, &v1)) return;

    const int64_t sat = (std::strcmp(op, "add") == 0) ? stlfix::cfx::add(v0, d)
                                                      : stlfix::cfx::mul(v0, d);

    static std::atomic<int> n_sample_add{0};
    static std::atomic<int> n_sample_mul{0};
    std::atomic<int>& n_sample = (std::strcmp(op, "add") == 0) ? n_sample_add : n_sample_mul;
    constexpr int kSampleLog = 3;
    if (n_sample.fetch_add(1, std::memory_order_relaxed) < kSampleLog) {
        logf("SAMPLE %s v0=%lld d=%lld game=%lld sat=%lld %s", name, (long long)v0, (long long)d,
             (long long)v1, (long long)sat, v1 == sat ? "一致" : "分歧");
    }

    if (v1 != sat) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT %s v0=%lld d=%lld game=%lld sat=%lld", name, (long long)v0, (long long)d,
                 (long long)v1, (long long)sat);
#if SATFIX_REPLACE
        // 把饱和值写回：这是唯一会改存档状态的一步，所以默认（REPLACE=0）不执行。
        auto access = reinterpret_cast<FnAccessVarPtr>(helper_addr("access_var_pointer"));
        auto setvar = reinterpret_cast<FnSetVariable>(helper_addr("cvars_set"));
        if (access != nullptr && setvar != nullptr) {
            const void* nm = static_cast<const char*>(self) + kVarNameOff;
            const long long vars = access(scope, nm);
            if (vars != 0) {
                g_replaced.fetch_add(1, std::memory_order_relaxed);
                setvar(reinterpret_cast<const void*>(vars), nm, sat);
            }
        }
#endif
    }
}

void detour_var_mul(const void* self, const void* scope) {
    const int idx = kIdxVarMultiply;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();
    if (g_settings.enabled && g_settings.verify_variables)
        shadow_variable("multiply_variable", "mul", self, scope, g_hook_var_mul);
    else
        g_hook_var_mul.call(self, scope);
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
}

//  4b) CAddVariableEffect::ExecuteActual —— 变量加法
//      反编译（FUN_141777800）：写回 `GetValue(self+0xf0) + 条目[+0x38]`，
//      与 Linux CAddVariableEffect::ExecuteActual 的 `puVar2 + lVar3` 一致（纯加法）。
//      （g_hook_var_add 的声明在上一节的变量系统公共段里。）
void detour_var_add(const void* self, const void* scope) {
    const int idx = kIdxVarAdd;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();
    if (g_settings.enabled && g_settings.verify_variables)
        shadow_variable("add_variable", "add", self, scope, g_hook_var_add);
    else
        g_hook_var_add.call(self, scope);
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
}

whk::TypedHook<FnGetRoundedFp15> g_hook_get_rounded_fp15;

long long detour_get_rounded_fp15(const long long* fp15_bits) {
    const int idx = kIdxGetRoundedFp15;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();
    // OBSERVE：只计数 + 记录首次调用，不读参数、不判罚
    const long long r = g_hook_get_rounded_fp15.call(fp15_bits);
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

//  5) CFixedPoint::RoundTo(CFixedPoint const&) —— 非 sret
//         long long fn(long long* self /*rcx，会被就地改写*/, const long long* divisor /*rdx*/)
//      反编译：*param_1 = lVar3 - lVar3 % lVar2; return lVar3 / lVar2;
//      OBSERVE：只记"被调用过"，并顺带观察 divisor 是否为 0（Linux 侧也是记这个）。
using FnRoundTo = long long (*)(long long* self, const long long* divisor);

whk::TypedHook<FnRoundTo> g_hook_round_to;

long long detour_round_to(long long* self, const long long* divisor) {
    const int idx = kIdxRoundTo;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    long long d = 0;
    const bool d_ok = whk::safe_read(&d, divisor, sizeof d);
    const long long r = g_hook_round_to.call(self, divisor);

    // OBSERVE：divisor == 0 会让游戏做除零（x86 上会 #DE 崩掉），所以这一条值得记
    if (d_ok && d == 0) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events) logf("EVENT RoundTo divisor == 0！（游戏会除零）");
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

//  6) CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&) —— sret + 两个参数
//         long long* fn(long long* ret /*rcx*/, const long long* a /*rdx*/, const long long* b /*r8*/)
//      OBSERVE：只记"被调用过"（Linux 侧也是只记参数平方会溢出的量级；
//      多项式逼近重写等价参考实现风险太高，见 Linux README 第 5 节）。
using FnAtan2 = long long* (*)(long long* ret, const long long* a, const long long* b);

whk::TypedHook<FnAtan2> g_hook_atan2;

long long* detour_atan2(long long* ret, const long long* a, const long long* b) {
    const int idx = kIdxAtan2;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();
    long long* const r = g_hook_atan2.call(ret, a, b);
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

// ===========================================================================
// Sqrt 家族
//
//  两个都是 sret：longlong* fn(longlong* ret /*rcx*/, const longlong* src /*rdx*/)
//  （Linux 版返回 ulong 走 RAX，Windows 版走 sret —— 同一算法两种 ABI 表达，
//    签名以 Windows 的实际机器码为准。）
// ===========================================================================
//  **两个函数的参数顺序是相反的 —— 这是活体探针抓出来的**：
//      Sqrt     : *param_1 = result;  src = *param_2   ->  (out /*rcx*/, src /*rdx*/)
//      SafeSqrt : src = *param_1;     *param_2 = result ->  (src /*rcx*/, out /*rdx*/)
//  我最初两个都按 (out, src) 写，探针立刻暴露了 SafeSqrt 错：
//  它的返回槽一直是我预置的哨兵 0x5A5A5A5A5A5A5A5A（= 6510615555426900570），
//  五个输入全都"返回"同一个数 —— 说明写回落在了别处。
//  教训：同一个类里的相邻成员，参数顺序**不一定一致**；必须逐个按函数体定，不能类推。
using FnSqrt     = long long* (*)(long long* out, const long long* src);
using FnSafeSqrt = long long* (*)(const long long* src, long long* out);

whk::TypedHook<FnSqrt> g_hook_sqrt;
whk::TypedHook<FnSafeSqrt> g_hook_safe_sqrt;

//  INPUT_GUARD：CFixedPoint::Sqrt() const
//
//  Linux 侧判据：负输入会被当成巨大无符号数去迭代，结果无意义。
//  这里只判定、只记一行；REPLACE 模式下把输入夹成 0（0 的平方根是 0，语义安全）。
long long* detour_sqrt(long long* ret, const long long* src) {
    const int idx = kIdxSqrt;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    long long x = 0;
    const bool ok = whk::safe_read(&x, src, sizeof x);
    if (ok && x < 0) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT Sqrt x=%lld (%.4f) 为负 —— 原实现会当无符号迭代", (long long)x,
                 static_cast<double>(x) / 1e5);
#if SATFIX_REPLACE
        const long long zero = 0;
        g_replaced.fetch_add(1, std::memory_order_relaxed);
        return g_hook_sqrt.call(ret, &zero);
#endif
    }
    long long* const r = g_hook_sqrt.call(ret, src);
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

//  OBSERVE：CFixedPoint::SafeSqrt() const
//
//  它自己会处理小于安全域下界的输入（乘 100 进域），所以正常路径是安全的；
//  唯一可疑的仍是负输入。只记一行，不替换。
long long* detour_safe_sqrt(const long long* src, long long* out) {
    const int idx = kIdxSafeSqrt;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    long long x = 0;
    if (whk::safe_read(&x, src, sizeof x) && x < 0) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT SafeSqrt x=%lld (%.4f) 为负", (long long)x,
                 static_cast<double>(x) / 1e5);
    }
    long long* const r = g_hook_safe_sqrt.call(src, out);
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

//  NCombatRules::CalcMilitaryPowerExponent —— 军力指数（两个精度版本）
//
//  ABI（两个同形）：sret —— `longlong* fn(longlong* out /*rcx*/,
//                                        const longlong* base /*rdx*/,
//                                        const longlong* exp  /*r8*/)`
//
//  **注意参数顺序与 Linux 相反**：Linux 是 (out, 指数, 底数)，Windows 是 (out, 底数, 指数)。
//  这是本项目第 4 次遇到「同族函数 ABI 顺序不一致」，所以这里不类推、按函数体定。
//
//  OBSERVE：与 Linux 同 —— 只记录「中间积会撑爆 int64」的调用，不改数值。
//  pow 的等价饱和实现风险高（要复现它的 log2/exp2 定点迭代），
//  而这两个函数的调用量不大，观测价值 > 替换价值。
using FnMpe = long long* (*)(long long* out, const long long* base, const long long* exp);

whk::TypedHook<FnMpe> g_hook_mpe15;
whk::TypedHook<FnMpe> g_hook_mpe7;

void shadow_mpe(const char* name, int idx, whk::TypedHook<FnMpe>& hk, long long* out,
                const long long* base, const long long* exp) {
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    long long vb = 0, ve = 0;
    const bool ok = whk::safe_read(&vb, base, sizeof vb) && whk::safe_read(&ve, exp, sizeof ve);
    long long* const r = hk.call(out, base, exp);

    // 判据：两个操作数的**中间积**是否撑爆 int64。
    // 这一步与 Linux 侧同构，且不需要复现 pow 本体 —— 溢出必然先发生在乘积上。
    if (ok) {
        // MSVC 没有 __int128，所以用「除法反推」判溢出（不引入 128 位类型）。
        bool of = false;
        if (ve != 0) {
            if (vb > 0)      of = (ve > 0) ? (vb > INT64_MAX / ve) : (ve < INT64_MIN / vb);
            else if (vb < 0) of = (ve > 0) ? (vb < INT64_MIN / ve) : (vb < INT64_MAX / ve);
        }
        if (of) {
            g_events.fetch_add(1, std::memory_order_relaxed);
            if (g_settings.verbose_events)
                logf("EVENT %s base=%lld exp=%lld -> %lld（中间积超 int64，已 wrap）", name,
                     (long long)vb, (long long)ve,
                     (long long)((r != nullptr) ? *r : 0));
        }
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
}

long long* detour_mpe15(long long* out, const long long* base, const long long* exp) {
    shadow_mpe("CalcMilitaryPowerExponent<15>", kIdxMpe15, g_hook_mpe15, out, base, exp);
    return out;
}

long long* detour_mpe7(long long* out, const long long* base, const long long* exp) {
    shadow_mpe("CalcMilitaryPowerExponent<7>", kIdxMpe7, g_hook_mpe7, out, base, exp);
    return out;
}

//  CPopJob::CalcDiplomaticWeight(CPopGroup const&) const —— 外交权重
//
//  ABI：sret —— `longlong* fn(const void* self /*rcx*/, longlong* ret /*rdx*/,
//                             const void* group /*r8*/)`
//  函数体末尾 `*param_2 = uVar5; return param_2;` 确认返回槽在 rdx。
//
//  OBSERVE：外交权重是各项（人口基数 × 幸福度 × 经济…）的加权和，**不可能为负**。
//  所以判据很干脆：返回负数、或量级离谱 = 几乎必然是 wrap。
//  这个判据不需要复算，也不需要知道 CModifier 内部结构 —— 与 Linux 侧同。
//
//  这个目标是**用户实测后期最容易出问题**的一个，所以优先补上。
using FnDiploWeight = long long* (*)(const void* self, long long* ret, const void* group);

whk::TypedHook<FnDiploWeight> g_hook_diplo_weight;

/// 正常外交权重的量级上限（CFixedPoint 存储值，1e5 = 1 游戏单位）。
/// 权重是加权和，正常到 1e6 量级就很夸张了；1e17 只用来抓「明显 wrap 过」的值。
constexpr long long kDiploWeightSane = 100000000000000000LL;

long long* detour_diplo_weight(const void* self, long long* ret, const void* group) {
    const int idx = kIdxDiploWeight;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();
    long long* const r = g_hook_diplo_weight.call(self, ret, group);

    const long long v = (r != nullptr) ? *r : 0;

    if (v < 0 || v > kDiploWeightSane) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT CalcDiplomaticWeight 返回 %lld (%.4f) —— 权重应为非负，疑似溢出",
                 (long long)v, static_cast<double>(v) / 1e5);
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

//  17) NShipUtil::CalcAverageDamagePerDay —— 设计师面板的「伤害」
//
//  ABI（由唯一调用者 FUN_140c9e3f0 的 L142-143 确证，**不是 sret**）：
//      void fn(void* obj /*rcx*/, int idx /*edx*/, long long* out /*r8*/, void* param_4 /*r9*/)
//  它**没有返回值** —— 结果写进 out 结构。这是与 Linux 版最大的差异：
//  Linux 的同一个函数 `return local_b8`（值在 rax），Windows 版改成写 out。
//
//  体内末尾（L699-710）就是溢出点：
//      lVar9 = local_128 + 100000;                    // factor = add + 1.0
//      if (lVar22 + 0xb504f333U < 0x16a09e667 && local_128 + 0xb50679d3U < 0x16a09e667)
//          lVar9 = (lVar9 * lVar22) / 100000;         // ★ 裸 64 位乘，会 wrap
//      else { ...拆分回退... }
//
//  OBSERVE：只观测不替换。原因是它的输出结构语义还没逆清 —— 硬回写有写坏
//  其它字段的风险（一个结构里可能有多个统计值）。判据很硬：**伤害不可能为负**，
//  所以负值或超过 int64 上界（9.2e13 游戏单位）就几乎必然是 wrap。
//
//  ⚠️ 结构偏移 `+0x98` 是**反编译读出来的**，不是从符号推的，所以打日志时
//  也把它带出来，方便以后要升级成 EXACT 时核对。
constexpr long long kDamageSane = 9223372036854775807LL / 100000;  // 9.2e13 游戏单位
/// 伤害结果在**第 1 个参数那个对象**里的偏移。
///
/// ⚠️ 踩坑记录：函数体里写的是 `*(longlong *)(param_1 + 0x98) = lVar9`
/// （L844，另有 L783/L792 两处同址写入），param_1 就是 rcx 传进来的那个对象 ——
/// **不是**第 3 个参数。我第一版按「out 参数」读 `*out`，结果钩子装了、
/// 被调用 13128 次却一条 EVENT 都没有，因为那个位置根本没有伤害值。
constexpr int64_t kDamageOutOff = 0x98;

using FnDamagePerDay = void (*)(void* obj, int idx, long long* out, void* param_4);
whk::TypedHook<FnDamagePerDay> g_hook_damage;

void detour_damage_per_day(void* obj, int idx, long long* out, void* param_4) {
    const int k = kIdxDamagePerDay;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[k].fetch_add(1, std::memory_order_relaxed);
    note_first_call(k);
    game_thread_pump();

    g_hook_damage.call(obj, idx, out, param_4);

    // 诊断：把**多个候选位置**一次全打出来，用来定位伤害值到底写在哪。
    //   背景：面板「伤害」显示 -4380077663777.92（溢出），而 obj+0x98 读到 0 或 24.5
    //   这类小值 —— 值不在我以为的位置。函数体里出现过三个候选：
    //   param_1+0x38 / param_1+0x98 / 第 3 参数那块缓冲。与其继续猜，一次全读出来。
    if (g_settings.diag_recompute_calls > 0) {
        static std::atomic<int> shown_first{0};
        static std::atomic<int> shown_big{0};
        long long a = 0, b = 0, c0 = 0, c1 = 0, d = 0;
        if (obj != nullptr) {
            whk::fast_read(&a, static_cast<const char*>(obj) + 0x38, sizeof a);
            whk::fast_read(&b, static_cast<const char*>(obj) + 0x98, sizeof b);
        }
        if (out != nullptr) {
            const char* op = reinterpret_cast<const char*>(out);
            whk::fast_read(&c0, op, sizeof c0);
            whk::fast_read(&c1, op + 8, sizeof c1);
            whk::fast_read(&d, op + 0x98, sizeof d);
        }
        constexpr long long kBig = 1000000000000LL;  // > 1000 万游戏单位
        const bool big = (a > kBig || a < -kBig || b > kBig || b < -kBig || c0 > kBig ||
                          c0 < -kBig || c1 > kBig || c1 < -kBig || d > kBig || d < -kBig);
        const bool first = shown_first.fetch_add(1, std::memory_order_relaxed) < 4;
        const bool show_big = big && shown_big.fetch_add(1, std::memory_order_relaxed) < 24;
        if (first || show_big)
            logf("DIAG dmg obj=%p obj+38=%lld obj+98=%lld out0=%lld out8=%lld out98=%lld%s", obj,
                 a, b, c0, c1, d, big ? "  <<有大值" : "");
    }

    if (obj == nullptr) {
        maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
        return;
    }
    long long v = 0;
    if (!whk::fast_read(&v, static_cast<const char*>(obj) + kDamageOutOff, sizeof v)) {
        maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
        return;
    }
    if (v < 0 || v > kDamageSane) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT CalcAverageDamagePerDay 伤害=%lld (%.4f) —— 应为非负且 <= %lld，疑似 wrap",
                 v, static_cast<double>(v) / 1e5, (long long)kDamageSane);
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
}
//
//  ABI（三个函数同形，均由函数体确证）：
//      long long* fn(long long* ret /*rcx*/, const void* design /*rdx*/,
//                    const void* mods /*r8*/, const void* fleet /*r9*/,
//                    const void* tooltip /*栈*/)
//  体内以 `*param_1 = ...` 写返回值并 `return param_1` —— 与 Atan2 同样的 sret 形态。
//
//  ★ 为什么原来只能 OBSERVE，现在能做 EXACT
//  ---------------------------------------
//  上限 = 船体尺寸基础值 × 一连串乘法修正，其中大量乘法被**内联**，
//  现有的 ApplyModifierMult 钩子抓不到 —— 这是 Linux 侧把它列为 OBSERVE 的原因。
//  但读 Windows 函数体发现：那条算式**没有内联到无法复算的程度**，
//  它是由几个可独立调用的原语拼出来的（都是游戏自己的函数，见 HELPERS）：
//
//      size   = ship_size_of(design)                 // CShipSize
//      base   = *(design + <off>)                    // off: hull 0x10 / shield 0x130 / armor 0x70
//      base  += modifier_value(size, mods, type_a)   // type_a: hull 0x1e / shield 0x2e / armor 0x24
//      add    = modifier_value(size, mods, type_b)   // type_b: hull 0x1f / shield 0x2f / armor 0x25
//      factor = add + 100000                         // ← ★ 游戏在这里自己兜底
//      if (factor < 0) factor = 0
//      result = base * factor / 100000               // 走「安全域判定 + 拆分回退」
//
//  **「为什么溢出后是 0」的确切答案就在这里**：`add + 100000` 溢出 wrap 成负数后，
//  游戏把 factor 夹成 0，于是 result = base × 0 / 100000 = 0。
//  也就是说 0 **不是**我们算出来的，是游戏自己算出来的；Linux 的设计正是要在
//  这一步 `return sat`（返回数学上正确的饱和值），而 Windows 侧此前只是"看着它变成 0"。
//
//  ★ 判据：等值比对（与 Linux 完全同构）
//  ------------------------------------
//  用饱和算术重算一遍，与游戏写回的值比：
//    - 相等  -> 没有溢出，什么都不做（这是绝大多数情况）
//    - 不等  -> 原版那一步 wrap 了
//  好处：误差不放大。重算若差 1 ULP，只会把那台船改 1 ULP。
//
//  ★ 写回额外加一道闸：必须「不等」**且**「游戏值呈现 wrap 特征」
//  -----------------------------------------------------------
//  重算漏了船级修正（0x1c8/0x1c9 等，条件性生效）时，"不等"也可能来自我们的遗漏
//  而不是游戏的溢出。所以只在**游戏值本身就是 wrap 产物**（负数，或 0 而重算为正）
//  时才回写。漏项只会让重算值偏小，而偏小的一侧不会把正常值判成溢出 —— 方向安全。
using FnMaxHp = long long* (*)(long long* ret, const void* design, const void* mods,
                               const void* fleet, const void* tooltip);

/// 每个 ModifierType 流经 ApplyModifierMult 的次数（诊断用，见 detour_apply_mul）。
/// 声明在 detour_max_hp 之前：那里的 SAMPLE 会打这张直方图。
std::atomic<uint64_t> g_type_hits[64];

/// 「加算溢出塌成 0」的判定与封顶（见 detour_max_hp 里的详细说明）。
///
/// 倍率阈值：正常舰船的护盾/装甲倍率在 1~10 倍量级（实测 110468 = 1.10 倍）。
/// 1e7 倍（factor 1e12）已经远超任何正常配置，配上 0 基数就是溢出现场。
constexpr int64_t kCollapseFactor = 1000000000000LL;  ///< = 1e7 倍
/// 封顶值：INT64_MAX/1e5 换算回存储值就是 int64 上界本身。
/// 即「92 万亿游戏单位」那个天花板 —— 用户描述的那个数。
constexpr int64_t kSaturateCap = INT64_MAX;

/// 重算链的两个原语（只解析地址、不装钩子，见 HELPERS）。
using FnShipSizeOf    = void* (*)(const void* design);
using FnModifierValue = long long* (*)(const void* size, long long* out, const void* mods,
                                       int type);

/// 三个上限函数各自的「配方」—— 常量全部由**读函数体**得出，不是照抄 Linux。
/// （巧合的是偏移与 ModifierType 都与 Linux 一致，但那是核对出来的结论，不是假设。）
///
/// `type_class_base` / `type_class_mul` 是**条件性**船级修正：
/// 游戏在 `(fleet 虚调用 != 0) && FUN_140c67d40(fleet) < 2` 成立时才加
/// （护盾 L228-233）。那个条件依赖 CFleet 的虚表与一个尚未逆清的函数，
/// 所以这里**乐观地总是加上**，再由写回闸（见 detour_max_hp）挡住可能的误判。
struct MaxHpRecipe {
    int64_t design_off;       ///< design 里基础值的偏移
    int     type_add;         ///< 加算修正的 ModifierType
    int     type_mul;         ///< 乘算修正的 ModifierType
    int     type_class_base;  ///< 船级修正（加到 base），0 = 未建模
    int     type_class_mul;   ///< 船级修正（加到 add），0 = 未建模
    /// 这个上限的「值」是否住在**加算项**里（而不是基础值）。
    ///
    /// 实测（同一条 design 的正常舰船，见日志 DIAG 行）：
    ///   shield base=0        add_in=2861907747   <- 值在加算项
    ///   armor  base=0        add_in=2861907747   <- 与护盾完全相同
    ///   hull   base=5e9      add_in=0            <- 值在基础值，加算项恒为 0
    /// 这决定了「加算项被塌成 0」这条判据能不能用：对护盾/装甲，
    /// `add_in == 0` 是异常（值本该在这）；对船体，它是**正常状态**，
    /// 拿它当判据会误伤。所以按目标分别开关。
    bool    add_carries_value;
    /// 按舰船等级索引的额外乘算修正表（VA 的低 32 位；0 = 不建模）。
    uint32_t class_table_rva;
};

/// 上限函数体内那张**按舰船等级**索引的修正类型表（VA 的低 32 位）。
///
/// 三个函数里都有这一段（形状相同，只有表地址不同）：
///     bVar1  = *(byte *)(design + 0x468);              // 舰船等级下标
///     tbl    = &DAT_1428xxxx + bVar1 * 4;              // 该等级的 ModifierType
///     for (i = 0; i < *(int *)(mods + 0x1c); ++i)
///         if (*(int *)(*(long long *)(mods + 0x10) + i*4) == *tbl) {
///             v = *(long long *)(i*0x10 + *(long long *)(mods + 0x38));
///             if (掩码 bit5) { if (v < 0) v = 0; if (v > 1.0) v = 1.0; }
///             add += v;                                 // ★ 加到 **add_mul**
///             break;
///         }
///
/// **为什么必须建模**：漏掉它时重算会系统性偏小。实测一例
/// （日志 NOTE 行）：游戏=21304430712 而我们重算=1782290712 —— 差 13 倍，
/// 正是这一项没算。这就是船体此前一直「重算≠游戏」的原因。
///
/// **与 modifier_value 的区别**：这里是**内联**展开，结尾**不做**
/// `FUN_140d2c080(size, type)` 那一项相加（那一步只出现在 FUN_140d29dd0 里）。
/// 所以不能直接复用 modifier_value，必须自己扫表。
constexpr uint32_t kClassTableShield = 0x28167acu;
constexpr uint32_t kClassTableArmor  = 0x2816774u;
constexpr uint32_t kClassTableHull   = 0x281673cu;
/// 舰船等级下标在 design 里的偏移（三个函数都用 0x468）。
constexpr int64_t kShipClassOff = 0x468;

constexpr MaxHpRecipe kRecipeShield = {0x130, 0x2e, 0x2f, 0x1c8, 0x1c9, true,
                                       kClassTableShield};
constexpr MaxHpRecipe kRecipeArmor  = {0x70, 0x24, 0x25, 0x1c6, 0x1c7, true, kClassTableArmor};
// 船体：add_carries_value = false —— 它的 add_in 正常就是 0，不能当溢出判据。
// 它的溢出走另一条路（base 非 0，乘爆后 wrap），由下面的 `v < 0` 那条分支兜。
constexpr MaxHpRecipe kRecipeHull   = {0x10, 0x1e, 0x1f, 0, 0, false, kClassTableHull};

/// 用游戏自己的原语饱和重算上限。成功返回 true 并把结果写进 `*out`。
/// 任一原语没解析到（辅助函数签名校验失败）就返回 false，调用方退化成「只认负数」。
///
/// `base_raw_out` 回传**未加任何修正**的 design 原始值：写回闸用它区分
/// 「这船本来就没护盾（base==0）」与「base 有值但 factor 被夹成了 0」。
/// 把 CModifier 的 (type, value) 表转成一行日志。
/// 布局由 FUN_140d29dd0 确证：条目数在 +0x1c，type 数组在 +0x10（int32，步长 4），
/// 值数组在 +0x38（int64，步长 0x10）。
void dump_mods(const void* mods, char* buf, size_t cap) {
    size_t off = 0;
    off += (size_t)snprintf(buf + off, cap - off, " mods[");
    if (mods != nullptr) {
        const char* m = static_cast<const char*>(mods);
        int32_t n = 0;
        const void* types = nullptr;
        const void* vals = nullptr;
        if (whk::safe_read(&n, m + 0x1c, sizeof n) && whk::safe_read(&types, m + 0x10, sizeof types) &&
            whk::safe_read(&vals, m + 0x38, sizeof vals) && types != nullptr && vals != nullptr) {
            if (n > 64) n = 64;
            for (int32_t i = 0; i < n && off + 32 < cap; ++i) {
                int32_t t = 0;
                int64_t v = 0;
                if (!whk::safe_read(&t, static_cast<const char*>(types) + (size_t)i * 4, sizeof t))
                    break;
                if (!whk::safe_read(&v, static_cast<const char*>(vals) + (size_t)i * 0x10, sizeof v))
                    break;
                off += (size_t)snprintf(buf + off, cap - off, "%s%x=%lld", i ? " " : "", t,
                                        (long long)v);
            }
        }
        off += (size_t)snprintf(buf + off, cap - off, "] n=%d", n);
    } else {
        off += (size_t)snprintf(buf + off, cap - off, "null]");
    }
}

/// 护盾/装甲/船体上限这一族的 ModifierType。
/// 由三个上限函数体读出：hull 0x1e/0x1f、shield 0x2e/0x2f + 0x1c8/0x1c9、
/// armor 0x24/0x25 + 0x1c6/0x1c7。另外把邻近的 0x22/0x23、0x29/0x2a 也纳入 ——
/// 它们是同一张表里护盾/装甲相关的兄弟项，一起看才看得出是谁把量级推爆的。
inline bool is_hp_modifier_type(int t) {
    switch (t) {
        case 0x1e: case 0x1f:                       // hull add/mul
        case 0x24: case 0x25: case 0x1c6: case 0x1c7:  // armor
        case 0x2e: case 0x2f: case 0x1c8: case 0x1c9:  // shield
        case 0x22: case 0x23: case 0x29: case 0x2a:    // 邻近兄弟项
            return true;
        default:
            return false;
    }
}

/// 上限函数体内那张**按舰船等级**索引的修正类型表。
///
/// 三个函数里都有这一段（形状相同，只有表地址不同）：
///     bVar1  = *(byte *)(design + 0x468);              // 舰船等级下标
///     tbl    = &DAT_1428xxxx + bVar1 * 4;              // 该等级的 ModifierType
///     for (i = 0; i < *(int *)(mods + 0x1c); ++i)
///         if (*(int *)(*(long long *)(mods + 0x10) + i*4) == *tbl) {
///             v = *(long long *)(i*0x10 + *(long long *)(mods + 0x38));
///             if (掩码 bit5) { if (v < 0) v = 0; if (v > 1.0) v = 1.0; }
///             add += v;                                 // ★ 加到 **add_mul**
///             break;
///         }
///
/// **为什么必须建模**：漏掉它时重算会系统性偏小。实测一例
/// （日志 NOTE 行）：游戏=21304430712 而我们重算=1782290712 —— 差 13 倍，
/// 正是这一项没算。
///
/// **与 modifier_value 的区别**：这里是**内联**展开，结尾**不做**
/// `FUN_140d2c080(size, type)` 那一项相加（那一步只出现在 FUN_140d29dd0 里）。
/// 所以不能直接复用 modifier_value，必须自己扫表。
///
/// 内联版「按类型取值」：扫 mods 的 type 数组，命中就取对应值并按掩码夹取。
/// 不做 FUN_140d2c080 的相加（与游戏内联形态一致）。
int64_t inline_mod_lookup(const void* mods, int type) {
    if (mods == nullptr) return 0;
    const char* m = static_cast<const char*>(mods);
    int32_t n = 0;
    const void* types = nullptr;
    const void* vals = nullptr;
    // 热路径：全部用 fast_read（地址来自游戏传入的 CModifier*，可信）。
    if (!whk::fast_read(&n, m + 0x1c, sizeof n) || n <= 0) return 0;
    if (!whk::fast_read(&types, m + 0x10, sizeof types) || types == nullptr) return 0;
    if (!whk::fast_read(&vals, m + 0x38, sizeof vals) || vals == nullptr) return 0;
    for (int32_t i = 0; i < n; ++i) {
        int32_t t = 0;
        if (!whk::fast_read(&t, static_cast<const char*>(types) + (size_t)i * 4, sizeof t)) return 0;
        if (t != type) continue;
        int64_t v = 0;
        if (!whk::fast_read(&v, static_cast<const char*>(vals) + (size_t)i * 0x10, sizeof v)) return 0;
        void* tbl = whk::image_base_plus(0x2814390u);  // ModifierType 元数据表
        if (tbl != nullptr) {
            uint32_t mask = 0;
            if (whk::fast_read(&mask, static_cast<const char*>(tbl) + (size_t)type * 0xb0 + 0xa8,
                               sizeof mask) &&
                ((mask >> 5) & 1u)) {
                if (v < 0) return 0;
                if (v > cfx::kOne) return cfx::kOne;
            }
        }
        return v;
    }
    return 0;
}

/// 按舰船等级查那个额外的乘算修正（见 kClassTable* 的说明）。
int64_t ship_class_mod(const void* design, const void* mods, uint32_t table_rva) {
    if (design == nullptr || table_rva == 0) return 0;
    uint8_t cls = 0;
    if (!whk::fast_read(&cls, static_cast<const char*>(design) + kShipClassOff, sizeof cls)) return 0;
    const void* table = whk::image_base_plus(table_rva);
    if (table == nullptr) return 0;
    int32_t type = 0;
    if (!whk::fast_read(&type, static_cast<const char*>(table) + (size_t)cls * 4, sizeof type))
        return 0;
    return inline_mod_lookup(mods, type);
}

/// 重算的中间量，用于诊断「为什么没报」。
/// stage: 0=未开始 1=helper 缺失 2=size 为空 3=读 base 失败 4=modifier 返回空
///        5=完成 6=factor<=0（真值为负，按 Linux 同款跳过）
struct MaxHpDetail {
    int     stage = 0;
    int64_t base_raw = 0, add_in = 0, add_mul = 0, cls_base = 0, cls_mul = 0;
    int64_t cls_tbl = 0;
    int64_t factor = 0, sat = 0;
};

bool recompute_max_hp(const MaxHpRecipe& r, const void* design, const void* mods, int64_t* out,
                      MaxHpDetail* d) {
    if (d != nullptr) *d = MaxHpDetail{};
    auto ship_size_of = reinterpret_cast<FnShipSizeOf>(helper_addr("ship_size_of"));
    auto get_modifier = reinterpret_cast<FnModifierValue>(helper_addr("modifier_value"));
    if (ship_size_of == nullptr || get_modifier == nullptr) {
        if (d) d->stage = 1;
        return false;
    }
    if (design == nullptr || mods == nullptr || out == nullptr) {
        if (d) d->stage = 1;
        return false;
    }

    void* size = ship_size_of(design);
    if (size == nullptr) {
        if (d) d->stage = 2;
        return false;
    }

    int64_t base = 0;
    if (!whk::fast_read(&base, static_cast<const char*>(design) + r.design_off, sizeof base)) {
        if (d) d->stage = 3;
        return false;
    }
    if (d) d->base_raw = base;

    int64_t v = 0;
    if (get_modifier(size, &v, mods, r.type_add) == nullptr) {
        if (d) d->stage = 4;
        return false;
    }
    if (d) d->add_in = v;
    base = add_sat(base, v);

    int64_t add = 0;
    if (get_modifier(size, &add, mods, r.type_mul) == nullptr) {
        if (d) d->stage = 4;
        return false;
    }
    if (d) d->add_mul = add;

    // 船级修正：游戏用的是**同一个** modifier_value 原语（护盾 L230-233），
    // 所以这里直接复用，不要自己重写查表（重写会漏掉它内部的 d2c080 相加项）。
    if (r.type_class_base != 0) {
        int64_t c = 0;
        if (get_modifier(size, &c, mods, r.type_class_base) != nullptr) {
            if (d) d->cls_base = c;
            base = add_sat(base, c);
        }
    }
    if (r.type_class_mul != 0) {
        int64_t c = 0;
        if (get_modifier(size, &c, mods, r.type_class_mul) != nullptr) {
            if (d) d->cls_mul = c;
            add = add_sat(add, c);
        }
    }

    // 按舰船等级的额外乘算修正（内联形态，见 kClassTable* 的说明）。
    // 漏掉它会让重算系统性偏小 —— 这正是船体此前一直「重算≠游戏」的原因。
    if (r.class_table_rva != 0) {
        const int64_t cm = ship_class_mod(design, mods, r.class_table_rva);
        if (d) d->cls_tbl = cm;
        add = add_sat(add, cm);
    }

    const int64_t factor = add_sat(add, cfx::kOne);
    if (d) d->factor = factor;
    if (factor <= 0) {  // 真值非正 —— Linux 侧同款跳过（`if (factor > 0)`）
        if (d) d->stage = 6;
        return false;
    }
    *out = cfx::mul(base, factor);
    if (d) {
        d->sat = *out;
        d->stage = 5;
    }
    return true;
}

whk::TypedHook<FnMaxHp> g_hook_shield_max;
whk::TypedHook<FnMaxHp> g_hook_armor_max;
whk::TypedHook<FnMaxHp> g_hook_hull_max;

long long* detour_max_hp(const char* name, int idx, whk::TypedHook<FnMaxHp>& hk,
                         const MaxHpRecipe& recipe, long long* ret, const void* design,
                         const void* mods, const void* fleet, const void* tooltip) {
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();
    long long* const r = hk.call(ret, design, mods, fleet, tooltip);

    const long long v = (r != nullptr) ? *r : 0;

    // ★★ 快速路径（性能关键）—— 必须放在**所有**逐调用开销之前
    // ------------------------------------------------------
    // 下面**所有**回写分支都要求 `v <= 0`：
    //   * 「塌成 0」需要 add_in==0，而护盾/装甲的 base 恒为 0 → 游戏值必然是 0；
    //   * 「wrap」要求 v < 0 或 v == 0。
    // 正常舰船的 v 是正数（实测 6023399996 等），对它做重算是**纯浪费** ——
    // 而三个上限函数各约 157 万次调用，每次重算要 4~6 次游戏函数调用
    // （含一次虚调用）+ 扫 46 项修正表。
    //
    // 实测教训（2026-10-11 用户反馈「过一天的时间变长、流畅度降低」）：
    // 就是这里。加了这条快速路径后，正常舰船只花一次比较 + 一次原子加。
    //
    // 诊断开启时（diag_recompute_calls > 0）不走快速路径，以便观察完整链路；
    // 那个开关默认关闭，只在排查时短时打开。
    const bool want_diag = g_settings.diag_recompute_calls > 0;
    if (v > 0 && !want_diag) {
        maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
        return r;
    }

    // 采样：留作实机核对重算是否逐位一致（不一致但没到回写阈值时尤其有用）。
    bool is_sample = false;
    {
        static std::atomic<uint64_t> n{0};
        const uint64_t c = n.fetch_add(1, std::memory_order_relaxed) + 1;
        if (c == 500 || c == 5000 || c == 50000 || c == 200000) {
            is_sample = true;
            logf("SAMPLE#%llu %s 上限 = %lld (%.4f)", (unsigned long long)c, name,
                 (long long)v, static_cast<double>(v) / 1e5);
            // 同一批把 ApplyModifierMult 的 ModifierType 直方图打出来，
            // 回答「护盾/装甲/船体族到底有没有流经那个出口」。
            if (g_settings.diag_modifier_calls > 0) {
                char hb[900];
                size_t off = 0;
                off += (size_t)snprintf(hb + off, sizeof hb - off, "TYPES");
                for (int t = 0; t < 64; ++t) {
                    const uint64_t n2 = g_type_hits[t].load(std::memory_order_relaxed);
                    if (n2 != 0 && off + 16 < sizeof hb)
                        off += (size_t)snprintf(hb + off, sizeof hb - off, " %x=%llu", t,
                                                (unsigned long long)n2);
                }
                logf("%s", hb);
            }
        }
    }

    int64_t sat = 0;
    MaxHpDetail d;
    const bool ok = g_settings.verify_max_hp && recompute_max_hp(recipe, design, mods, &sat, &d);

    // 诊断：把重算链的每一段打出来。「溢出没被抓到」时这是唯一能定位卡在哪一段的证据。
    //   ⚠️ 只看头 N 次调用是**没用**的：开局那批是数据库加载，design/mods 都是假指针
    //      （实测 mods = 0x7FEFF0，栈地址），全读 0。所以改成只在两种有意义的点打印：
    //        * 采样点（与 SAMPLE 同一批，已知有真实值）
    //        * 前 N 次「游戏值非 0」的调用（= 真在设计舰船）
    if (g_settings.diag_recompute_calls > 0) {
        static std::atomic<int> shown_nonzero{0};
        const bool want_nonzero =
            (v != 0) && (shown_nonzero.fetch_add(1, std::memory_order_relaxed) <
                         g_settings.diag_recompute_calls);
        if (is_sample || want_nonzero) {
            char mbuf[1400];
            dump_mods(mods, mbuf, sizeof mbuf);
            logf("DIAG %s 游戏=%lld design=%p stage=%d base=%lld add_in=%lld "
                 "add_mul=%lld cls_b=%lld cls_m=%lld cls_tbl=%lld factor=%lld sat=%lld%s",
                 name, (long long)v, const_cast<void*>(design), d.stage,
                 (long long)d.base_raw, (long long)d.add_in, (long long)d.add_mul,
                 (long long)d.cls_base, (long long)d.cls_mul, (long long)d.cls_tbl,
                 (long long)d.factor, (long long)d.sat, mbuf);
        }
    }

    // 「护盾 0」这类症状的专用诊断：**游戏算出 0，但倍率巨大**。
    // 这说明不是这个函数算错了（重算与游戏一致，都得出 0），
    // 而是**输入本身已经是坏的** —— 基础值在上游就被写成了 0。
    // 记下整张修正表，用来反查是哪个修正把它堆到那么大。
    if (g_settings.diag_recompute_calls > 0 && v == 0 && d.stage == 5 &&
        d.factor > 1000000) {  // 倍率 > 10 倍才记，正常舰船远低于此
        static std::atomic<int> shown_zero{0};
        if (shown_zero.fetch_add(1, std::memory_order_relaxed) < 8) {
            char mbuf[1400];
            dump_mods(mods, mbuf, sizeof mbuf);
            logf("ZERO %s 游戏=0 但倍率=%lld（%.2f 倍）base=0 design=%p%s", name,
                 (long long)d.factor, static_cast<double>(d.factor) / 1e5,
                 const_cast<void*>(design), mbuf);
        }
    }

    if (ok) {
        // ★ 「溢出塌成 0」的封顶（2026-10-11 实测确认的根因）
        // ------------------------------------------------
        // 机制（三步，缺一不可）：
        //   1) 加算项的真值超过 9.2e13 游戏单位（= INT64_MAX/1e5），
        //      游戏自己的 mul 在拆分路径上 wrap 成**负数**；
        //   2) GetModifierValue 对掩码类型有兜底 `if (v < 0) v = 0`（FUN_140d29dd0），
        //      于是整项被夹成 **0**；
        //   3) factor = add + 1.0 随之变成 1.0？不 —— 见下。
        //
        // **三个函数共用同一个夹取**（逐个读体确认，行号各异但形状相同）：
        //      shield L353-356: lVar11 = lVar11 + 100000; if (lVar11 < 0) lVar11 = 0;
        //      armor  L293-296: uVar5  = lVar7  + 100000U; if ((longlong)(...) < 0) uVar5 = 0;
        //      hull   L380-383: lVar12 = lVar11 + 100000; if (lVar11 + 100000 < 0) lVar12 = 0;
        //   注意夹的是 **add + 1.0**，不是 add 本身：所以当 add 被塌成 0 时
        //   factor = 0 + 100000 = 1.0（**不是 0**）。于是：
        //      上限 = (base + 0) × 1.0 / 1e5
        //   护盾/装甲 base=0 -> 结果 0；船体 base=5e9 -> 结果 = base（**丢掉全部倍率**）。
        //   两者都是"数值被毁"，只是毁法不同。
        //
        // 实测证据（同一存档、同一条 design 指针）：
        //   正常舰船  装甲加算 0x24 = 2861907747  护盾加算 0x2e = 2861907747（两者相同）
        //   出问题那台 装甲加算 0x24 = 11000000000 护盾加算 0x2e = 0  ← 被塌掉
        //            护盾乘算 0x2f = 1000000000000000（1e10 游戏单位 = 1e12%）
        //   用户原话「吃了一个 buff 计算大于 92 万亿溢出了」与
        //   INT64_MAX/1e5 = 92233720368547 **精确吻合**。
        //
        // 判据：**加算项读到 0、而倍率巨大**（正常舰船是 1.1 倍量级，1e7 倍不可能是真值）。
        //   只对 `add_carries_value` 的目标（护盾/装甲）生效 —— 它们的值本该住在加算项里，
        //   读到 0 就是被塌掉。船体的加算项**正常就是 0**，用这条会误伤，已排除。
        //   不需要额外要求 v==0：护盾/装甲的 base 恒为 0，add_in==0 时结果必然是 0。
        // 封顶到 INT64_MAX —— 也就是那个「92 万亿」的上限。
        const bool collapsed =
            recipe.add_carries_value && d.add_in == 0 && d.factor >= kCollapseFactor;
        if (collapsed) {
            g_events.fetch_add(1, std::memory_order_relaxed);
            // 限流：舰船详情面板每帧都会重算同一个 design，不限流一次点击能刷上万行
            // （实测 19899 行把日志打满）。按 design 指针记「报过」，每条 design 只报一次。
            bool first_for_this_design = false;
            if (g_settings.verbose_events) {
                static std::atomic<uint64_t> last_design{0};
                static std::atomic<int> logged{0};
                const uint64_t dp = reinterpret_cast<uint64_t>(design);
                if (logged.load(std::memory_order_relaxed) < g_settings.collapse_log_limit &&
                    last_design.exchange(dp, std::memory_order_relaxed) != dp) {
                    logged.fetch_add(1, std::memory_order_relaxed);
                    first_for_this_design = true;
                }
            }
            if (first_for_this_design)
                logf("EVENT %s 加算溢出塌成 0（倍率=%lld = %.2f 倍）-> 封顶到 %lld%s", name,
                     (long long)d.factor, static_cast<double>(d.factor) / 1e5,
                     (long long)kSaturateCap,
#if SATFIX_REPLACE
                     " [已回写]"
#else
                     " [影子模式，未改数值]"
#endif
                );
#if SATFIX_REPLACE
            if (r != nullptr) {
                g_replaced.fetch_add(1, std::memory_order_relaxed);
                *r = kSaturateCap;
            }
#endif
            maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
            return r;
        }
        if (sat != v) {
            // 重算与游戏不一致。只在**游戏值本身呈现 wrap 特征**时才认定溢出：
            //   * v < 0            —— 上限不可能为负，铁证
            //   * v == 0 && base_raw > 0 && sat > 0
            //                      —— 就是那个「add+1.0 溢出 → factor 被夹成 0 → 结果 0」
            //                         的现场。要求 base_raw > 0 是为了排除「这船本来
            //                         就没有护盾」的正常 0，那种情况不该报。
            // 其余的不一致（重算与游戏分叉但游戏值看着正常）只记不罚，
            // 避免把正常值改坏 —— 宁可漏报，不可误改。
            const bool wrapped = (v < 0) || (v == 0 && d.base_raw > 0 && sat > 0);
            if (wrapped) {
                g_events.fetch_add(1, std::memory_order_relaxed);
                if (g_settings.verbose_events)
                    logf("EVENT %s 上限溢出 游戏=%lld (%.4f) 饱和=%lld (%.4f) "
                         "design_base=%lld%s",
                         name, (long long)v, static_cast<double>(v) / 1e5, (long long)sat,
                         static_cast<double>(sat) / 1e5, (long long)d.base_raw,
#if SATFIX_REPLACE
                         " [已回写]"
#else
                         " [影子模式，未改数值]"
#endif
                    );
#if SATFIX_REPLACE
                if (r != nullptr) {
                    g_replaced.fetch_add(1, std::memory_order_relaxed);
                    *r = sat;
                }
#endif
            } else if (g_settings.log_recompute_mismatch) {
                // 诊断用，默认关闭：实测船体上限的重算会与游戏系统性不等
                // （它的算式里还有一段条件性累加循环尚未建模），
                // 每次调用都记会把 4000 行的日志刷满、把真信号淹掉。
                logf("NOTE %s 重算≠游戏但未达回写阈值 游戏=%lld 重算=%lld design_base=%lld",
                     name, (long long)v, (long long)sat, (long long)d.base_raw);
            }
        }
    } else if (v < 0) {
        // 退化路径（重算原语没解析到）：只认「结果为负」这条硬判据，与 Linux 同。
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT %s 上限为负 %lld (%.4f) -> 置零%s", name, (long long)v,
                 static_cast<double>(v) / 1e5,
#if SATFIX_REPLACE
                 ""
#else
                 "（影子模式，未改数值）"
#endif
            );
#if SATFIX_REPLACE
        if (r != nullptr) {
            g_replaced.fetch_add(1, std::memory_order_relaxed);
            *r = 0;
        }
#endif
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

long long* detour_shield_max(long long* ret, const void* design, const void* mods,
                             const void* fleet, const void* tooltip) {
    return detour_max_hp("CalcMaxShieldHitPoints", kIdxShieldMax, g_hook_shield_max, kRecipeShield,
                         ret, design, mods, fleet, tooltip);
}

long long* detour_armor_max(long long* ret, const void* design, const void* mods,
                            const void* fleet, const void* tooltip) {
    return detour_max_hp("CalcMaxArmorHitPoints", kIdxArmorMax, g_hook_armor_max, kRecipeArmor, ret,
                         design, mods, fleet, tooltip);
}

long long* detour_hull_max(long long* ret, const void* design, const void* mods, const void* fleet,
                           const void* tooltip) {
    return detour_max_hp("CalcMaxHitPoints", kIdxHullMax, g_hook_hull_max, kRecipeHull, ret, design,
                         mods, fleet, tooltip);
}

//  7) CModifier::ApplyModifierMult —— 数值放大的主出口，EXACT
//
//  ABI（由函数体 + 调用点确证）：
//      long long* fn(long long* ret /*rcx, 实际倍率*/,
//                    long long* value /*rdx, CFixedPoint& 会被就地改写*/,
//                    const void* modifier /*r8*/,
//                    int modifier_type /*r9d*/,
//                    bool  stack_flag /*栈上传*/)
//
//  **为什么能做成真正的 EXACT**：这个函数会**返回实际生效的倍率**
//  （`*param_1 = local_10`）。所以影子复算不需要重新实现 CModifier 的类型表查找：
//      1. 先读入参 v0 = *value
//      2. 调原函数，拿到真实倍率 m_eff，以及被就地改写后的 v_game = *value
//      3. 用 cfx::mul(v0, m_eff) 算精确饱和值 —— 这一项与游戏的算式**完全同构**
//         （游戏的拆分路径是 (X%1e5)*Y/1e5 + (X/1e5)*Y 的等价变形，真值相同）
//      4. 比较 v_game 与 sat：不一致就说明游戏 wrap 了
//  这条链绕开了「逆清 CModifier 内部结构」这个难题。
using FnApplyMul = long long* (*)(long long* ret, long long* value, const void* modifier,
                                  int modifier_type, bool stack_flag);
using FnApplyMulFp15 = long long* (*)(long long* ret, long long* fp15_value,
                                      const void* modifier, int modifier_type, bool stack_flag);

whk::TypedHook<FnApplyMul> g_hook_apply_mul;
whk::TypedHook<FnApplyMulFp15> g_hook_apply_mul_fp15;

/// 两个重载共用的影子逻辑：v_game 已经是原函数写回后的值。
/// `is_fp15` 决定用 >>15 还是 /1e5 的语义。
/// ApplyModifierMult 的影子复算 + 回写。
///
/// `value` 是那个被就地改写的 CFixedPoint&，`m_eff` 是原函数返回的实际生效倍率。
/// 游戏算的是 `v0 * m_eff`（定点，除 1e5）；我们用饱和版本重算一遍比对，
/// 不一致就是游戏 wrap 了 —— 回写模式下把饱和值写回 `*value`。
///
/// 这里能安全回写是因为**游戏自己已经把结果写进 `*value` 了**：
/// 我们只是在一个已经写好的槽上覆盖一个更合理的值，不改变调用约定、
/// 不需要逆清 CModifier 的内部结构。
void shadow_apply_mul(const char* name, int64_t v0, int64_t m_eff, int64_t v_game, bool is_fp15,
                      long long* value) {
    const int64_t sat = is_fp15 ? stlfix::mul_shift_sat(v0, m_eff, stlfix::kFp15Shift)
                                : cfx::mul(v0, m_eff);
    if (v_game != sat) {
        g_events.fetch_add(1, std::memory_order_relaxed);
        if (g_settings.verbose_events)
            logf("EVENT %s v0=%lld mult=%lld game=%lld sat=%lld", name, (long long)v0,
                 (long long)m_eff, (long long)v_game, (long long)sat);
#if SATFIX_REPLACE
        // 写回饱和值。value 是游戏传进来的那个槽，非 const，可以直接改。
        if (value != nullptr) {
            g_replaced.fetch_add(1, std::memory_order_relaxed);
            *value = sat;
        }
#endif
    }
}

long long* detour_apply_mul(long long* ret, long long* value, const void* modifier,
                           int modifier_type, bool stack_flag) {
    const int idx = kIdxApplyMul;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    int64_t v0 = 0;
    const bool ok = whk::fast_read(&v0, value, sizeof v0);  // 热路径（463 万次）

    long long* const r = g_hook_apply_mul.call(ret, value, modifier, modifier_type, stack_flag);

    if (ok && r != nullptr) {
        int64_t m_eff = 0, v_game = 0;
        whk::fast_read(&m_eff, r, sizeof m_eff);
        whk::fast_read(&v_game, value, sizeof v_game);
        shadow_apply_mul("ApplyModifierMult(cfx)", v0, m_eff, v_game, false, value);

        // 统计每个 ModifierType 的调用次数（前 64 个类型），用来回答
        // 「护盾/装甲/船体那一族到底有没有流经这个出口」。
        // 用户那个「护盾 0」的现场里 0x2e=0 / 0x2f=1e15，
        // 如果这些 type 一次都没从这里过，就说明污染在**别的出口**。
        // 默认关：这条路 463 万次调用，常态开着每次都要多一次原子加。
        if (g_settings.diag_modifier_calls > 0 && modifier_type >= 0 && modifier_type < 64) {
            g_type_hits[modifier_type].fetch_add(1, std::memory_order_relaxed);
        }
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

long long* detour_apply_mul_fp15(long long* ret, long long* fp15_value, const void* modifier,
                                int modifier_type, bool stack_flag) {
    const int idx = kIdxApplyMulFp15;
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_fn_calls[idx].fetch_add(1, std::memory_order_relaxed);
    note_first_call(idx);
    game_thread_pump();

    int64_t v0 = 0;
    const bool ok = whk::fast_read(&v0, fp15_value, sizeof v0);  // 热路径

    long long* const r =
        g_hook_apply_mul_fp15.call(ret, fp15_value, modifier, modifier_type, stack_flag);

    if (ok && r != nullptr) {
        int64_t m_eff = 0, v_game = 0;
        whk::fast_read(&m_eff, r, sizeof m_eff);
        whk::fast_read(&v_game, fp15_value, sizeof v_game);
        shadow_apply_mul("ApplyModifierMult(fp15)", v0, m_eff, v_game, true, fp15_value);
    }
    maybe_heartbeat(g_calls.load(std::memory_order_relaxed));
    return r;
}

// ===========================================================================
// 活体探针（live probe）—— 用真实游戏函数走通「EXACT 检出」这条链
//
//  为什么需要它
//  -----------
//  `cfx_get_rounded` / `cfx_to_fp15` 的判定逻辑只有读档进局才会被自然调用到，
//  而"读档"依赖人工操作。但这两个目标都是**纯函数**：读一个 int64、返回一个
//  int64、不碰任何游戏状态。所以可以直接拿极值喂进去。
//
//  这样做验证到的东西比读档还硬：
//    detour -> 蹦床 -> **真实的游戏函数** -> 判定 -> EVENT
//  整条链都在真进程里跑，而且用的是游戏自己的机器码算出来的返回值。
//
//  安全性：
//    * 只在**自己的初始化线程**上调用。这两个函数是纯的（没有全局副作用、
//      不碰引擎状态），所以不违反手册 6.3 那条（那条针对的是引擎/UI/逻辑函数）。
//    * 全程 SEH 包住；任何异常都只是少打几行日志，不会影响游戏。
//    * 只有 SATFIX_WIN_FORCE=1 时才跑（留给自动化/回归用，正常游玩不受影响）。
//
//  注意：探针的返回值随模式而变 —— 影子模式下是游戏原本的值，
//        回写模式下是饱和值。两者日志上长得一样，所以要看 kBuildMode 那行区分。
// ===========================================================================
void run_live_probe() {
    char b[8] = {};
    if (GetEnvironmentVariableA("SATFIX_WIN_FORCE", b, sizeof b) == 0 || b[0] != '1') return;

    logf("活体探针开始（两个 EXACT 目标都会被真的调用一次）");

    // ---- GetRounded: 非 sret，返回槽在 rax；参数是 this 指针 ----
    if (g_hook_get_rounded.trampoline() != nullptr) {
        const int64_t inputs[] = {
            123456,                    // 常规值：不该分歧
            INT64_MAX,                 // 上界溢出（已实测复现）
            9223372036854725807LL,     // 上界最后一个安全值
            9223372036854725808LL,     // 上界第一个坏值
            INT64_MIN,                 // 下界溢出
        };
        for (int64_t x : inputs) {
            __try {
                const long long got = detour_get_rounded(&x);
                logf("探针 GetRounded in=%lld -> game=%lld", (long long)x, (long long)got);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                logf("探针 GetRounded in=%lld -> 异常 0x%08lX", (long long)x,
                     GetExceptionCode());
            }
        }

        // ---- 回写路径的**端到端**验证 ----
        // 上面几行只能证明「detour 返回值正确」，证明不了「REPLACE 真的把值改掉了」——
        // 影子模式下 detour 照样返回 game 值，两者在日志上长得一样。
        // 这里绕开 detour 的返回值，直接读**游戏自己的输出槽**：
        //   传一个必然溢出的输入，看调用之后槽里是 game 的 wrap 值还是我们写的饱和值。
        // 这与真机路径走同一段代码（同一 detour、同一判定），所以结论可外推。
        {
            const int64_t bad = INT64_MAX;
            int64_t slot = bad;
            __try {
                const long long ret = detour_get_rounded(&slot);
                const long long expect_game = -92233720368547LL;  // wrap 后的值
                const long long expect_sat = 92233720368547LL;    // 饱和值
                // GetRounded 是**纯读**函数：它只读 *param_1、把结果放在返回值里，
                // 不写回入参（函数体：lVar1 = *param_1; ... return lVar2 / 100000;）。
                // 所以判据看**返回值**，不看输入槽 —— 输入槽本来就该保持原样。
                const char* verdict =
                    (ret == expect_sat)
                        ? "返回饱和值（REPLACE 生效）"
                        : (ret == expect_game ? "返回 wrap 值（REPLACE 未生效）" : "其它");
                logf("回写验证 GetRounded in=INT64_MAX -> 返回 %lld [%s]（期望 game=%lld sat=%lld）"
                     "（REPLACE=%d，输入槽 %lld 未变属正常）",
                     (long long)ret, verdict, (long long)expect_game, (long long)expect_sat,
                     (int)SATFIX_REPLACE, (long long)slot);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                logf("回写验证 GetRounded -> 异常 0x%08lX", GetExceptionCode());
            }
        }
    } else {
        logf("探针 GetRounded 跳过：该钩子没装上");
    }

    // ---- operator fpml<...,15>: 重新启用，用调用点确证的 ABI 探测 ----
    if (g_hook_to_fp15.trampoline() != nullptr) {
        const int64_t inputs[] = {123456, INT64_MAX, INT64_MIN, 0};
        for (int64_t x : inputs) {
            int64_t slot = 0;
            __try {
                // ABI：rcx = 源，rdx = 返回槽 -> C++ 参数顺序 (src, ret)
                detour_to_fp15(&x, &slot);
                logf("探针 to_fp15 in=%lld -> game=%lld", (long long)x, (long long)slot);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                logf("探针 to_fp15 in=%lld -> 异常 0x%08lX", (long long)x, GetExceptionCode());
            }
        }
    } else {
        logf("探针 to_fp15 跳过：该钩子没装上");
    }

    // ---- GetRounded(fp15): OBSERVE，只确认能被调用 ----
    if (g_hook_get_rounded_fp15.trampoline() != nullptr) {
        const int64_t fp15_bits[] = {0, 0x8000, -0x8000};
        for (int64_t bits : fp15_bits) {
            __try {
                const long long got = detour_get_rounded_fp15(&bits);
                logf("探针 GetRounded(fp15) bits=0x%llx -> %lld（OBSERVE，值本身不作判据）",
                     (unsigned long long)bits, (long long)got);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                logf("探针 GetRounded(fp15) bits=0x%llx -> 异常 0x%08lX",
                     (unsigned long long)bits, GetExceptionCode());
            }
        }
    }

    logf("活体探针结束：本次共 %llu 次调用、%llu 条 EVENT",
         (unsigned long long)g_calls.load(), (unsigned long long)g_events.load());

    // ---- RoundTo: 非 sret，rcx=this（就地改写），rdx=除数指针 ----
    if (g_hook_round_to.trampoline() != nullptr) {
        const int64_t divisors[] = {1000, 200000};
        for (int64_t d : divisors) {
            int64_t self = 1234567;
            __try {
                const long long q = detour_round_to(&self, &d);
                logf("探针 RoundTo self=1234567 div=%lld -> self'=%lld q=%lld", (long long)d,
                     (long long)self, (long long)q);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                logf("探针 RoundTo div=%lld -> 异常 0x%08lX", (long long)d, GetExceptionCode());
            }
        }
    } else {
        logf("探针 RoundTo 跳过：该钩子没装上");
    }

    // ---- Atan2: sret(rcx) + 两个 CFixedPoint 指针(rdx, r8) ----
    if (g_hook_atan2.trampoline() != nullptr) {
        const int64_t pairs[][2] = {{100000, 100000}, {0, 100000}, {100000, 0}};
        for (const auto& pr : pairs) {
            int64_t ret = 0;
            const int64_t ax = pr[0], bx = pr[1];
            __try {
                detour_atan2(&ret, &ax, &bx);
                logf("探针 Atan2 a=%lld b=%lld -> %lld（OBSERVE，值不作判据）", (long long)ax,
                     (long long)bx, (long long)ret);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                logf("探针 Atan2 a=%lld b=%lld -> 异常 0x%08lX", (long long)ax, (long long)bx,
                     GetExceptionCode());
            }
        }
    } else {
        logf("探针 Atan2 跳过：该钩子没装上");
    }

    // ---- Sqrt 家族：两个函数参数顺序相反，分别探 ----
    //   Sqrt     (out, src)  : 完全平方数输入应还原出原值
    //   SafeSqrt (src, out)  : 同上（它内部会先乘 100 进域再算，再除回来）
    //   负值输入用来验证 Sqrt 的 INPUT_GUARD 分支真的被走到
    {
        const long long inputs[] = {100000, 10000000000LL, 1, 0, -1};
        if (g_hook_sqrt.trampoline() != nullptr) {
            for (long long v : inputs) {
                long long ret = 0x5A5A5A5A5A5A5A5ALL;
                const long long src = v;
                __try {
                    g_hook_sqrt.call(&ret, &src);
                    logf("探针 Sqrt x=%lld (%.4f) -> %lld (%.4f)", (long long)v,
                         static_cast<double>(v) / 1e5, (long long)ret,
                         static_cast<double>(ret) / 1e5);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    logf("探针 Sqrt x=%lld -> 异常 0x%08lX", (long long)v, GetExceptionCode());
                }
            }
        } else {
            logf("探针 Sqrt 跳过：该钩子没装上");
        }
        if (g_hook_safe_sqrt.trampoline() != nullptr) {
            for (long long v : inputs) {
                long long ret = 0x5A5A5A5A5A5A5A5ALL;
                const long long src = v;
                __try {
                    g_hook_safe_sqrt.call(&src, &ret);
                    logf("探针 SafeSqrt x=%lld (%.4f) -> %lld (%.4f)", (long long)v,
                         static_cast<double>(v) / 1e5, (long long)ret,
                         static_cast<double>(ret) / 1e5);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    logf("探针 SafeSqrt x=%lld -> 异常 0x%08lX", (long long)v, GetExceptionCode());
                }
            }
        } else {
            logf("探针 SafeSqrt 跳过：该钩子没装上");
        }
    }

    // ---- CalcMax{Shield,Armor,}HitPoints 不在这里探针 ----
    // 这三个要读 design 对象里的成员表（param_2+0x10 / +0x130 / +0x70），
    // 传全零假对象只会让它们解引用空指针 -> AV，被 __except 记成「异常」，
    // 而「异常」既不能证明签名对也不能证明签名错，是**没有信息量的探针**。
    // 它们的 ABI 已由函数体（sret + `return param_1`）静态确证，
    // 运行时验证靠的是实机计数（见 EVIDENCE_live_gameplay.txt 的百万级调用）。

    logf("活体探针（扩展）结束：累计 %llu 次调用、%llu 条 EVENT",
         (unsigned long long)g_calls.load(), (unsigned long long)g_events.load());
}

// ===========================================================================
// 初始化
// ===========================================================================

std::atomic<bool> g_installed{false};
std::atomic<int> g_hooked{0};
std::atomic<int> g_skipped{0};

/// 这个进程是不是 stellaris.exe？
///
/// Linux 侧踩过坑：LD_PRELOAD 会被子进程继承，bash/cp/rm 每个都加载一遍并刷屏。
/// Windows 上启动器是在**游戏进程内**创建远程线程 LoadLibraryW，理论上不会污染
/// 别的进程；但用户也可能用 stl inject --pid 指错进程，所以还是查一下。
///
/// `SATFIX_WIN_FORCE=1` 绕过该检查：给离线自测用（对应 Linux 侧的 SATFIX_FORCE）。
/// 目标解析/签名校验依然会跑，所以绕过它不等于跳过安全检查。
bool is_stellaris_process() {
    {
        char b[8] = {};
        if (GetEnvironmentVariableA("SATFIX_WIN_FORCE", b, sizeof b) > 0 && b[0] == '1')
            return true;
    }
    wchar_t path[MAX_PATH * 2] = {};
    if (GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path))) == 0)
        return true;  // 查不到就别拦着
    const wchar_t* name = wcsrchr(path, L'\\');
    name = name ? name + 1 : path;
    return _wcsicmp(name, L"stellaris.exe") == 0;
}

void install_hooks() {
    // ---- 打开日志（手册 9.1）----
    CreateDirectoryW((plugin_dir() + L"logs").c_str(), nullptr);
    g_log = open_log_file(plugin_dir() + L"logs\\satfix.log");
    whk::set_logger(&whk_log);

    // ---- 第一行记版本/路径/构建（手册 9.1）----
    logf("satfix-win 0.2.0  REPLACE=%d  %s", SATFIX_REPLACE, kBuildMode);
    {
        wchar_t exe[MAX_PATH * 2] = {};
        GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(std::size(exe)));
        logf("游戏进程: %ls", exe);
    }
    logf("插件目录: %ls", plugin_dir().c_str());

    // ---- 构建身份自检（手册 7：两层都做）----
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(whk::image_base());
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(whk::image_base() + dos->e_lfanew);
    const DWORD ts = nt->FileHeader.TimeDateStamp;
    logf("exe build 0x%08X（期望 0x%08X）%s", ts, SATFIX_WIN_EXE_TIMESTAMP,
         ts == SATFIX_WIN_EXE_TIMESTAMP ? "" : "  <== 不匹配！");
    if (ts != SATFIX_WIN_EXE_TIMESTAMP) {
        logf("这个构建没有适配过，所有目标都会被签名校验挡下，插件静默退出。");
        return;
    }

    // ---- 配置 ----
    bool found = false;
    g_settings = read_settings(&found);
    logf("设置: %s", found ? "config\\satfix.ini" : "文件缺失，用内置默认值");
    if (!g_settings.enabled) {
        logf("enabled=false，不安装钩子。");
        return;
    }

    // ---- 判定逻辑自检 ----
    // 在**真实游戏进程里**跑一遍 satfix_decision 的自检向量表。
    // 这样"判定逻辑对不对"就有实机证据，不必依赖"读档之后刚好有 EVENT"。
    {
        int selftest_failures = satfix_decision::run_selftest(
            nullptr, [](void*, const char* line, bool bad) {
                logf("自检 %s%s", line, bad ? "   <== 失败" : "");
            });
        logf("判定逻辑自检：%s", selftest_failures == 0 ? "全部通过" : "有失败！");
    }
    // ---- 解析目标 ----
    Resolved res[kTargetCount];
    const int n = resolve_targets(res, kTargetCount);
    logf("目标: 签名校验通过 %d/%d，未定位 %d（见下），本构建适配 %d",
         n, kTargetCount, kUnresolvedCount, kTargetCount);

    // ---- 解析辅助函数（变量系统 EXACT 的前提）----
    const int nh = resolve_helpers();
    logf("辅助函数: 签名校验通过 %d/%d（变量系统 EXACT %s）", nh, kHelperCount,
         nh == kHelperCount ? "可用" : "退化为只计数");

    // ---- 安装 ----
    for (int i = 0; i < n; ++i) {
        const Target& t = *res[i].t;
        bool ok = false;
        if (t.strategy == kDisabled) {
            logf("跳过 %s：地址与函数体已确证，但 ABI 未确认（活体探针实测读到常数），"
                 "装上去在 REPLACE 模式下会写坏内存。见目标表里的证据。",
                 t.key);
            ++g_skipped;
            continue;
        }
        if (std::strcmp(t.key, "cfx_get_rounded") == 0)
            ok = g_hook_get_rounded.install(res[i].addr, &detour_get_rounded);
        else if (std::strcmp(t.key, "cfx_to_fp15") == 0)
            ok = g_hook_to_fp15.install(res[i].addr, &detour_to_fp15);
        else if (std::strcmp(t.key, "var_multiply") == 0)
            ok = g_hook_var_mul.install(res[i].addr, &detour_var_mul);
        else if (std::strcmp(t.key, "var_add") == 0)
            ok = g_hook_var_add.install(res[i].addr, &detour_var_add);
        else if (std::strcmp(t.key, "cfx_sqrt") == 0)
            ok = g_hook_sqrt.install(res[i].addr, &detour_sqrt);
        else if (std::strcmp(t.key, "cfx_safe_sqrt") == 0)
            ok = g_hook_safe_sqrt.install(res[i].addr, &detour_safe_sqrt);
        else if (std::strcmp(t.key, "diplo_weight") == 0)
            ok = g_hook_diplo_weight.install(res[i].addr, &detour_diplo_weight);
        else if (std::strcmp(t.key, "mpe15") == 0)
            ok = g_hook_mpe15.install(res[i].addr, &detour_mpe15);
        else if (std::strcmp(t.key, "mpe7") == 0)
            ok = g_hook_mpe7.install(res[i].addr, &detour_mpe7);
        else if (std::strcmp(t.key, "cfx_get_rounded_fp15") == 0)
            ok = g_hook_get_rounded_fp15.install(res[i].addr, &detour_get_rounded_fp15);
        else if (std::strcmp(t.key, "apply_mul_cfx") == 0)
            ok = g_hook_apply_mul.install(res[i].addr, &detour_apply_mul);
        else if (std::strcmp(t.key, "apply_mul_fp15") == 0)
            ok = g_hook_apply_mul_fp15.install(res[i].addr, &detour_apply_mul_fp15);
        else if (std::strcmp(t.key, "cfx_round_to") == 0)
            ok = g_hook_round_to.install(res[i].addr, &detour_round_to);
        else if (std::strcmp(t.key, "cfx_atan2") == 0)
            ok = g_hook_atan2.install(res[i].addr, &detour_atan2);
        else if (std::strcmp(t.key, "shield_max") == 0)
            ok = g_hook_shield_max.install(res[i].addr, &detour_shield_max);
        else if (std::strcmp(t.key, "armor_max") == 0)
            ok = g_hook_armor_max.install(res[i].addr, &detour_armor_max);
        else if (std::strcmp(t.key, "hull_max") == 0)
            ok = g_hook_hull_max.install(res[i].addr, &detour_hull_max);
        else if (std::strcmp(t.key, "damage_per_day") == 0)
            ok = g_hook_damage.install(res[i].addr, &detour_damage_per_day);
        else {
            logf("目标 %s 没有对应的 detour（目标表与代码不同步）", t.key);
            continue;
        }
        if (ok) {
            g_hooked.fetch_add(1, std::memory_order_relaxed);
            logf("hooked %s @ %p（%s，策略 %d）", t.key, res[i].addr, t.desc, (int)t.strategy);
        } else {
            g_skipped.fetch_add(1, std::memory_order_relaxed);
            logf("FAILED to hook %s @ %p", t.key, res[i].addr);
        }
    }

    logf("共装上 %d/%d 个钩子（跳过 %d）%s", g_hooked.load(), kTargetCount,
         g_skipped.load(), SATFIX_REPLACE ? "  [REPLACE 已开]" : "  [影子模式]");

    if constexpr (kUnresolvedCount > 0) {
        logf("未安装的条目（%d 个，其中含已判定「Windows 侧无对应代码」者）：", kUnresolvedCount);
        for (int i = 0; i < kUnresolvedCount; ++i) logf("    %s", kUnresolved[i]);
    }

    // ---- 配置热重载：只看修改时间，真正重读放到主线程泵 ----
    logf("就绪。设置改动会在游戏运行中被自动重读；日志上限 %d 行。", SATFIX_MAX_LOGS);

    // ---- 活体探针（仅 SATFIX_WIN_FORCE=1 时）----
    // 放在最后：此时 4 个钩子都已装好。
    run_live_probe();
}

/// 自己的线程：只做日志/文件/等待，绝不碰引擎（手册 6.3）。
DWORD WINAPI init_thread(LPVOID) {
    if (!is_stellaris_process()) return 0;
    __try {
        install_hooks();
        g_installed.store(true, std::memory_order_release);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logf("初始化时发生异常 0x%08lX，插件停用。", GetExceptionCode());
        return 0;
    }

    FILETIME last = settings_mtime();
    for (;;) {
        Sleep(2000);
        const FILETIME now = settings_mtime();
        if (CompareFileTime(&now, &last) != 0) {
            last = now;
            g_reload_requested.store(true, std::memory_order_release);
        }
    }
}

}  // namespace

// ===========================================================================
// 供外部（调试/自动化）查询的导出
// ===========================================================================

extern "C" __declspec(dllexport) void satfix_win_stats(uint64_t* calls, uint64_t* events,
                                                       uint64_t* hooked, uint64_t* replaced) {
    if (calls) *calls = g_calls.load();
    if (events) *events = g_events.load();
    if (hooked) *hooked = (uint64_t)g_hooked.load();
    if (replaced) *replaced = g_replaced.load();
}

// ===========================================================================
// DllMain —— 手册 6.1：加载器锁内，只创建一个线程
// ===========================================================================

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        // 不等待、不 LoadLibrary、不碰引擎、不做文件/网络 —— 全在自己的线程里
        if (HANDLE t = CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr))
            CloseHandle(t);
    }
    return TRUE;
}
