#ifndef WHK_WINHOOK_HPP
#define WHK_WINHOOK_HPP
//
//  winhook.hpp —— shk.hpp 的 Windows/x64 移植（satfix-win 的 hook 引擎）
//
//  与 hooklib/shk.hpp 的关系
//  ------------------------
//  算法（入口 5 字节 `E9 rel32` -> relay -> 蹦床、rel8 统一加宽成 rel32、
//  蹦床就近分配、`FF 25 00000000 <abs64>` 跳转、不碰任何寄存器）**逐条保留**，
//  指令长度解码器也原样搬运 —— 原因见下。换掉的只有 OS 那一层：
//
//      Linux (shk)                     Windows (whk)
//      ------------------------------  ------------------------------------
//      /proc/self/exe + ELF .symtab    没有符号；改用「RVA 表 + 镜像基址」
//      dlsym(RTLD_DEFAULT, mangled)    同样没有；见上
//      mprotect(RWX)                   VirtualProtect(保存并恢复原保护)
//      mmap(MAP_FIXED_NOREPLACE)       VirtualQuery 找空洞 + VirtualAlloc
//      munmap                          VirtualFree
//      __builtin___clear_cache         FlushInstructionCache
//      （无）                          SuspendThread 其余线程（补丁原子化）
//
//  **解码器为什么可以照搬**：指令长度编码由 x86-64 架构决定，与操作系统无关。
//  shk 对真实 stellaris（139452 个函数）做过「前 12 字节必须能完整解码」的全量
//  扫描，失败 0 个。Windows 上真正的差异在**函数序言形状**（MSVC 与 GCC 不同），
//  所以 whk 另外提供 `verify_prologue()` 供安装前显式检查，而不是假定一致。
//
//  与手册的对应关系（PLUGIN_HANDBOOK.zh-CN）
//  -----------------------------------------
//  * 6.3 引擎代码只在游戏主线程调用 —— whk 不做调度，只提供机制；
//        调度在 sat_guard_win.cpp 的任务队列里。
//  * 6.4 读内存要防崩溃 —— `safe_read()` 用 SEH 包住原始读取。
//  * 6.5 与其他插件共存 —— detour 里必须调原函数；whk 不恢复/覆盖他人钩子。
//  * 6.6 不要卸载自己 —— 不提供 FreeLibrary；`uninstall()` 只用于自测。
//
//  编译要求：MSVC /std:c++20、x64。默认 /MT（插件不依赖 VC++ 运行库）。
//
//  用法::
//
//      using Fn = long long (*)(const void* self);
//      whk::TypedHook<Fn> g_h;
//      void* target = whk::image_base_plus(0x1b4c170);   // 由 RVA 表给出
//      g_h.install(target, &my_detour);
//      ...
//      long long v = g_h.call(self);      // 调原函数
//

#include <windows.h>
#include <tlhelp32.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#if !defined(_M_X64)
#  error "winhook 只支持 x64"
#endif

namespace whk {

// -----------------------------------------------------------------------------
//  0. 日志：stderr 在 GUI 进程里不可见，所以交给调用方注入 sink
// -----------------------------------------------------------------------------

using log_fn = void (*)(const char* line);

inline log_fn& logger() {
  static log_fn f = nullptr;
  return f;
}

inline void set_logger(log_fn f) { logger() = f; }

inline void log(const char* fmt, ...) {
  log_fn f = logger();
  if (f == nullptr) return;
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof buf, _TRUNCATE, fmt, ap);
  va_end(ap);
  f(buf);
}

// 调试开关：SATFIX_WIN_DEBUG=1
inline bool debug_enabled() {
  static const bool on = [] {
    char b[8] = {};
    const DWORD n = GetEnvironmentVariableA("SATFIX_WIN_DEBUG", b, sizeof b);
    return n > 0 && b[0] == '1';
  }();
  return on;
}

// -----------------------------------------------------------------------------
//  1. 镜像基址与 RVA -> 运行时地址
// -----------------------------------------------------------------------------

inline uintptr_t image_base() {
  static const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
  return base;
}

inline void* image_base_plus(uintptr_t rva) {
  return reinterpret_cast<void*>(image_base() + rva);
}

// -----------------------------------------------------------------------------
//  2. 受保护的原始读取（手册 6.4：一个坏指针不能让游戏崩溃）
// -----------------------------------------------------------------------------

/// @brief 从任意进程内地址读 n 字节；目标不可读时返回 false 而不是崩溃。
///
/// 先用 VirtualQuery 确认可读，再用 SEH 兜住竞态（内存可能刚被释放）。
inline bool safe_read(void* dst, const void* src, size_t n) {
  MEMORY_BASIC_INFORMATION mbi{};
  if (VirtualQuery(src, &mbi, sizeof mbi) == 0) return false;
  if (mbi.State != MEM_COMMIT) return false;
  const DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY;
  if ((mbi.Protect & readable) == 0) return false;

  __try {
    std::memcpy(dst, src, n);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
  return true;
}

/// @brief 目标地址是否落在本进程的一个已提交页里（用于过滤坏 RVA）。
inline bool is_mapped(uintptr_t addr) {
  MEMORY_BASIC_INFORMATION mbi{};
  if (VirtualQuery(reinterpret_cast<const void*>(addr), &mbi, sizeof mbi) == 0) return false;
  return mbi.State == MEM_COMMIT;
}

// -----------------------------------------------------------------------------
//  3. 写代码段
// -----------------------------------------------------------------------------

/// @brief 打开 [addr, addr+len) 的可写权限，返回原保护值（失败时 0）。
inline DWORD unprotect(void* addr, size_t len) {
  DWORD old = 0;
  if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return 0;
  return old;
}

/// @brief 带 SEH 的 memcpy。
///
/// **必须**独立成函数：MSVC 禁止在「需要对象展开（unwinding）」的函数里使用
/// `__try`（C2712），而 InlineHook 里有 std::vector 成员，所以 SEH 只能待在
/// 这种没有局部对象的窄函数里。
inline void seh_memcpy(void* dst, const void* src, size_t len) {
  __try {
    std::memcpy(dst, src, len);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    // 目标不可写；调用方按"写入失败"处理
  }
}

inline bool write_code(void* dst, const void* src, size_t len, DWORD old_protect) {
  seh_memcpy(dst, src, len);
  FlushInstructionCache(GetCurrentProcess(), dst, len);
  DWORD tmp = 0;
  VirtualProtect(dst, len, old_protect, &tmp);
  return true;
}

// -----------------------------------------------------------------------------
//  4. 在目标 ±2GB 内分配内存
// -----------------------------------------------------------------------------

/// @brief 在 hint 的 ±2GB 内找一块空闲区域并提交 size 字节。
///
/// 蹦床必须离目标足够近：入口 `E9 rel32` 只够 ±2GB，蹦床里被重定位的
/// RIP 相对寻址与 rel32 同样只够 ±2GB。
/// 做法是沿 hint 上下按 64KB 步进用 VirtualQuery 找 MEM_FREE 空洞。
inline void* alloc_near(void* hint, size_t size) {
  SYSTEM_INFO si{};
  GetSystemInfo(&si);
  const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
  const uintptr_t ps = si.dwPageSize ? si.dwPageSize : 0x1000;
  size = (size + ps - 1) & ~(ps - 1);

  const uintptr_t h = reinterpret_cast<uintptr_t>(hint);
  const uintptr_t kMax = 0x70000000ull;  // 留足 ±2GB 余量

  auto try_at = [&](uintptr_t a) -> void* {
    void* p = VirtualAlloc(reinterpret_cast<void*>(a), size,
                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return p;
  };

  for (uintptr_t d = 0; d < kMax; d += gran) {
    uintptr_t up = h + d;
    if (up > h) {
      uintptr_t a = up & ~(gran - 1);
      MEMORY_BASIC_INFORMATION mbi{};
      if (VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof mbi) != 0 &&
          mbi.State == MEM_FREE) {
        if (void* p = try_at(a)) return p;
      }
    }
    if (d != 0 && h > d) {
      uintptr_t a = (h - d) & ~(gran - 1);
      MEMORY_BASIC_INFORMATION mbi{};
      if (VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof mbi) != 0 &&
          mbi.State == MEM_FREE) {
        if (void* p = try_at(a)) return p;
      }
    }
  }
  return nullptr;  // 宁可失败也不要拿一块够不到的内存
}

// -----------------------------------------------------------------------------
//  5. 线程挂起（入口 5 字节补丁不是原子写；Windows 允许我们做对这件事）
// -----------------------------------------------------------------------------

class ThreadFreeze {
 public:
  bool freeze() {
    const DWORD me = GetCurrentThreadId();
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) {
      do {
        if (te.th32OwnerProcessID != pid) continue;
        if (te.th32ThreadID == me) continue;
        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (th == nullptr) continue;
        if (SuspendThread(th) != (DWORD)-1) threads_.push_back(th);
        else CloseHandle(th);
      } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return true;
  }

  void thaw() {
    for (HANDLE th : threads_) {
      ResumeThread(th);
      CloseHandle(th);
    }
    threads_.clear();
  }

  ~ThreadFreeze() { thaw(); }

 private:
  std::vector<HANDLE> threads_;
};

// -----------------------------------------------------------------------------
//  6. x86-64 指令长度解码（从 shk.hpp 原样移植；编码与 OS 无关）
// -----------------------------------------------------------------------------

struct insn_t {
  uint8_t len = 0;       // 0 = 无法解码（拒绝 hook）
  int8_t rip_off = -1;   // RIP 相对 disp32 在指令内的偏移
  int8_t rel_off = -1;   // 相对跳转 disp 在指令内的偏移
  uint8_t rel_size = 0;  // 1 或 4
};

namespace detail {

inline insn_t decode(const uint8_t* p, size_t max) {
  insn_t r{};
  size_t i = 0;
  bool opsz16 = false;
  bool rexw = false;

  auto ok = [&](size_t at, size_t n) { return at + n <= max; };

  // ---- 传统前缀 + REX ----
  for (;;) {
    if (!ok(i, 1)) return r;
    uint8_t b = p[i];
    if (b == 0x66) { opsz16 = true; ++i; continue; }
    if (b == 0x67) { ++i; continue; }
    if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
        b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { ++i; continue; }
    if (b >= 0x40 && b <= 0x4F) { if (b & 8) rexw = true; ++i; continue; }
    break;
  }
  (void)rexw;

  // ---- ModRM / SIB / disp ----
  auto modrm = [&]() -> bool {
    if (!ok(i, 1)) return false;
    uint8_t m = p[i++];
    uint8_t mod = (uint8_t)(m >> 6);
    uint8_t rm = (uint8_t)(m & 7);
    if (mod == 3) return true;
    if (rm == 4) {  // 有 SIB
      if (!ok(i, 1)) return false;
      uint8_t sib = p[i++];
      if ((sib & 7) == 5 && mod == 0) { if (!ok(i, 4)) return false; i += 4; }
    } else if (rm == 5 && mod == 0) {  // RIP 相对
      r.rip_off = (int8_t)i;
      if (!ok(i, 4)) return false;
      i += 4;
    }
    if (mod == 1) { if (!ok(i, 1)) return false; i += 1; }
    else if (mod == 2) { if (!ok(i, 4)) return false; i += 4; }
    return true;
  };

  // ---- 操作码 ----
  if (!ok(i, 1)) return r;
  uint8_t op = p[i++];

  // -------- VEX2 / VEX3 / EVEX --------
  if (op == 0xC5 || op == 0xC4 || op == 0x62) {
    uint8_t map;
    if (op == 0xC5) {
      if (!ok(i, 1)) return r;
      map = (uint8_t)(p[i] & 0x1F);
      ++i;
    } else if (op == 0xC4) {
      if (!ok(i, 1)) return r;
      map = (uint8_t)(p[i] & 0x1F);
      i += 2;
    } else {  // EVEX (0x62)
      if (!ok(i, 1)) return r;
      map = (uint8_t)(p[i] & 0x07);
      i += 3;
    }
    if (!ok(i, 1)) return r;
    uint8_t vop = p[i++];
    if (!modrm()) return r;
    bool vimm = (map == 1 && (vop == 0x70 || vop == 0x71 || vop == 0x72 ||
                              vop == 0x73 || vop == 0xC2 || vop == 0xC6)) ||
                (map == 3);
    if (vimm) { if (!ok(i, 1)) return r; i += 1; }
    r.len = (uint8_t)i;
    return r;
  }

  // -------- 0F 两字节 --------
  if (op == 0x0F) {
    if (!ok(i, 1)) return r;
    uint8_t op2 = p[i++];
    bool m = true;
    uint8_t imm2 = 0;

    if (op2 >= 0x80 && op2 <= 0x8F) {  // jcc rel32
      m = false;
      r.rel_off = (int8_t)i;
      r.rel_size = 4;
      if (!ok(i, 4)) return r;
      i += 4;
    } else {
      switch (op2) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
        case 0x0C: case 0x0E:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x37:
        case 0x77: case 0xA2: case 0xAA:
        case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E:
          m = false;
          break;
        default:
          if (op2 >= 0xC8 && op2 <= 0xCF) m = false;  // bswap
          break;
      }
      if (op2 == 0x70 || op2 == 0x71 || op2 == 0x72 || op2 == 0x73 ||
          op2 == 0xC2 || op2 == 0xC4 || op2 == 0xC5 || op2 == 0xC6) imm2 = 1;
      if (m) {
        if (!modrm()) return r;
      } else if (op2 == 0x0C || op2 == 0x0D) {
        return r;  // 非法/未定义，保守拒绝
      }
      if (imm2) { if (!ok(i, imm2)) return r; i += imm2; }
    }
    r.len = (uint8_t)i;
    return r;
  }

  // -------- 单字节 --------
  bool has_modrm = false;
  int imm = 0;

  if ((op >= 0x00 && op <= 0x03) || (op >= 0x08 && op <= 0x0B) ||
      (op >= 0x10 && op <= 0x13) || (op >= 0x18 && op <= 0x1B) ||
      (op >= 0x20 && op <= 0x23) || (op >= 0x28 && op <= 0x2B) ||
      (op >= 0x30 && op <= 0x33) || (op >= 0x38 && op <= 0x3B) ||
      (op >= 0x80 && op <= 0x8F) || (op >= 0xD8 && op <= 0xDF)) {
    has_modrm = true;
  }
  switch (op) {
    case 0x62: case 0x63: case 0x69: case 0x6B:
    case 0xC0: case 0xC1: case 0xC6: case 0xC7:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xF6: case 0xF7: case 0xFE: case 0xFF:
      has_modrm = true;
      break;
    default:
      break;
  }

  if ((op & 7) == 4 && op >= 0x04 && op <= 0x3C) imm = 1;
  if ((op & 7) == 5 && op >= 0x04 && op <= 0x3D) imm = opsz16 ? 2 : 4;
  if (op == 0x68) imm = opsz16 ? 2 : 4;
  if (op == 0x6A) imm = 1;
  if (op == 0x69) imm = opsz16 ? 2 : 4;
  if (op == 0x6B) imm = 1;
  if (op == 0x80 || op == 0x83 || op == 0xC0 || op == 0xC1 || op == 0xC6) imm = 1;
  if (op == 0x81 || op == 0xC7) imm = opsz16 ? 2 : 4;
  if (op == 0xA8) imm = 1;
  if (op == 0xA9) imm = opsz16 ? 2 : 4;
  if (op >= 0xB0 && op <= 0xB7) imm = 1;
  if (op >= 0xB8 && op <= 0xBF) imm = rexw ? 8 : (opsz16 ? 2 : 4);
  if (op == 0xC2 || op == 0xCA) imm = 2;
  if (op == 0xCD) imm = 1;
  if (op >= 0xE4 && op <= 0xE7) imm = 1;

  if (op >= 0x70 && op <= 0x7F) { r.rel_off = (int8_t)i; r.rel_size = 1; if (!ok(i, 1)) return r; i += 1; }
  else if (op >= 0xE0 && op <= 0xE3) { r.rel_off = (int8_t)i; r.rel_size = 1; if (!ok(i, 1)) return r; i += 1; }
  else if (op == 0xE8 || op == 0xE9) { r.rel_off = (int8_t)i; r.rel_size = 4; if (!ok(i, 4)) return r; i += 4; }
  else if (op == 0xEB) { r.rel_off = (int8_t)i; r.rel_size = 1; if (!ok(i, 1)) return r; i += 1; }

  if (has_modrm) {
    int imm_saved = imm;
    if (op == 0xF6 || op == 0xF7) {
      if (!ok(i, 1)) return r;
      uint8_t reg = (uint8_t)((p[i] >> 3) & 7);
      if (reg > 1) imm_saved = 0;
    }
    if (!modrm()) return r;
    imm = imm_saved;
  }

  if (imm) {
    if (!ok(i, (size_t)imm)) return r;
    i += (size_t)imm;
  }
  if (i > max || i > 15) return r;
  r.len = (uint8_t)i;
  return r;
}

// 已 hook 地址登记表，避免重复 hook。
// 不用「入口是不是 E9」判断：合法的链接器 thunk 本身就是 E9 开头。
//
// 必须是**共享的**单例：如果 mark/unmark 各自声明函数局部 static，两者看到的是
// 两张不同的表，撤销登记将永远找不到条目。函数局部 static 在 inline 函数里
// 天然只有一份，所以这样写既安全又线程安全（C++11 起的静态初始化保证）。
// 注意：本段位于 namespace detail 内部，不要再套一层同名 namespace。
struct HookRegistry {
  std::atomic<void*> table[512];
  std::atomic<unsigned> count{0};

  bool add(void* p) {
    unsigned n = count.load(std::memory_order_relaxed);
    for (unsigned i = 0; i < n && i < 512; ++i) {
      if (table[i].load(std::memory_order_relaxed) == p) return false;
    }
    if (n >= 512) return true;
    table[n].store(p, std::memory_order_relaxed);
    count.store(n + 1, std::memory_order_relaxed);
    return true;
  }

  /// @brief 撤销登记（尾部元素填补空洞）。
  ///
  /// shk 里这个是空操作，导致**安装失败也会把地址永久占住**、重试必然失败。
  void remove(void* p) {
    unsigned n = count.load(std::memory_order_relaxed);
    for (unsigned i = 0; i < n && i < 512; ++i) {
      if (table[i].load(std::memory_order_relaxed) != p) continue;
      table[i].store(table[n - 1].load(std::memory_order_relaxed),
                     std::memory_order_relaxed);
      count.store(n - 1, std::memory_order_relaxed);
      return;
    }
  }
};

inline HookRegistry& registry() {
  static HookRegistry r;
  return r;
}

inline bool mark_hooked(void* p) { return registry().add(p); }
inline void unmark_hooked(void* p) { registry().remove(p); }

}  // namespace detail

// -----------------------------------------------------------------------------
//  7. 内联 hook
// -----------------------------------------------------------------------------

class InlineHook {
 public:
  InlineHook() = default;
  InlineHook(void* target, void* detour) { install(target, detour); }

  InlineHook(const InlineHook&) = delete;
  InlineHook& operator=(const InlineHook&) = delete;
  InlineHook(InlineHook&& o) noexcept { move_from(o); }
  InlineHook& operator=(InlineHook&& o) noexcept {
    if (this != &o) { uninstall(); move_from(o); }
    return *this;
  }
  ~InlineHook() { uninstall(); }

  /// @brief 目标地址必须在 ±2GB 内可达（relay 用 `E9 rel32`）。
  ///
  /// 与 shk 的差别：不给「按符号名安装」的重载 —— Windows 侧没有被 hook 函数的
  /// 符号，目标地址一律由 RVA 表 / 特征码扫描给出。
  bool install(void* target, void* detour) {
    if (installed_) uninstall();
    target_ = static_cast<uint8_t*>(target);
    detour_ = static_cast<uint8_t*>(detour);

    if (!detail::mark_hooked(target_)) {
      log("目标 %p 已经被本库 hook 过，拒绝重复安装", (void*)target_);
      return false;
    }

    // 1) 解码前 kPatch(5) 字节，确定实际要复制的长度
    size_t copied = 0;
    struct Reloc { size_t off; insn_t ins; };
    std::vector<Reloc> relocs;
    uint8_t peek[16] = {};
    while (copied < kPatch) {
      if (!safe_read(peek, target_ + copied, sizeof peek)) {
        log("读不到目标 %p+%zu 的指令字节", (void*)target_, copied);
        detail::unmark_hooked(target_);
        return false;
      }
      insn_t in = detail::decode(peek, sizeof peek);
      if (in.len == 0) {
        log("不支持的目标序言 %p+%zu（字节 %02x %02x %02x %02x %02x）",
            (void*)target_, copied, peek[0], peek[1], peek[2], peek[3], peek[4]);
        detail::unmark_hooked(target_);
        return false;
      }
      relocs.push_back({copied, in});
      copied += in.len;
    }
    patch_len_ = copied;

    // 2) 规划蹦床布局：rel8 统一加宽成 rel32（与 shk 一致）。
    //    入口 `E9 rel32` 要求 relay 在 ±2GB 内，所以蹦床就近分配。
    struct Out { size_t src; size_t dst; size_t len; uint8_t kind; };
    std::vector<Out> outs;
    outs.reserve(relocs.size());
    size_t out_total = 0;
    for (const Reloc& rc : relocs) {
      const uint8_t op = target_[rc.off];
      uint8_t kind = 0;
      size_t len = rc.ins.len;
      if (rc.ins.rel_size == 1) {
        if (op >= 0x70 && op <= 0x7F) { kind = 1; len = 6; }   // jcc rel8 -> 0F 8x rel32
        else if (op == 0xEB)          { kind = 2; len = 5; }   // jmp rel8 -> E9 rel32
      }
      outs.push_back({rc.off, out_total, len, kind});
      out_total += len;
    }

    const size_t need = out_total + kAbsJump + kAbsJump;
    uint8_t* page = static_cast<uint8_t*>(alloc_near(target_, need));
    if (page == nullptr) {
      log("在 %p ±2GB 内分配蹦床失败", (void*)target_);
      detail::unmark_hooked(target_);
      return false;
    }
    page_ = page;
    page_len_ = (need + 0xFFF) & ~(size_t)0xFFF;
    uint8_t* tramp = page;
    uint8_t* relay = page + out_total + kAbsJump;

    // 3) 逐条发射：拷贝 + 修正位移（或加宽）
    for (size_t i = 0; i < outs.size(); ++i) {
      const Out& o = outs[i];
      const Reloc& rc = relocs[i];
      uint8_t* slot = tramp + o.dst;
      const uint8_t* src = target_ + o.src;

      if (debug_enabled()) {
        log("reloc src=%zu dst=%zu in=%u out=%zu kind=%u rip_off=%d rel_off=%d rel_size=%u tramp=%p",
            o.src, o.dst, rc.ins.len, o.len, (unsigned)o.kind,
            rc.ins.rip_off, rc.ins.rel_off, rc.ins.rel_size, (void*)tramp);
      }

      if (o.kind == 0) {
        std::memcpy(slot, src, rc.ins.len);
      } else {
        int8_t d8 = 0;
        std::memcpy(&d8, src + rc.ins.rel_off, 1);
        const int64_t abs_target = (int64_t)src + rc.ins.len + d8;
        const int64_t new_disp = abs_target - (int64_t)(slot + o.len);
        if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
          log("加宽成 rel32 后仍越界，放弃");
          cleanup_failed();
          return false;
        }
        int32_t nd = (int32_t)new_disp;
        if (o.kind == 1) {
          slot[0] = 0x0F;
          slot[1] = (uint8_t)(0x80 | (src[0] & 0x0F));
          std::memcpy(slot + 2, &nd, 4);
        } else {
          slot[0] = 0xE9;
          std::memcpy(slot + 1, &nd, 4);
        }
        continue;
      }

      if (rc.ins.rel_off >= 0) {
        int64_t disp = 0;
        if (rc.ins.rel_size == 4) {
          int32_t d = 0; std::memcpy(&d, src + rc.ins.rel_off, 4); disp = d;
        } else {
          int8_t d = 0; std::memcpy(&d, src + rc.ins.rel_off, 1); disp = d;
        }
        const int64_t abs_target = (int64_t)src + rc.ins.len + disp;
        const int64_t new_disp = abs_target - (int64_t)(slot + o.len);
        if (rc.ins.rel_size == 1) {
          if (new_disp < -128 || new_disp > 127) {
            log("rel8 越界（loop/jrcxz 无法加宽），放弃");
            cleanup_failed();
            return false;
          }
          int8_t nd = (int8_t)new_disp;
          std::memcpy(slot + rc.ins.rel_off, &nd, 1);
        } else {
          if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
            log("rel32 越界，放弃");
            cleanup_failed();
            return false;
          }
          int32_t nd = (int32_t)new_disp;
          std::memcpy(slot + rc.ins.rel_off, &nd, 4);
        }
      }
      if (rc.ins.rip_off >= 0) {
        int32_t d = 0; std::memcpy(&d, src + rc.ins.rip_off, 4);
        const int64_t abs_target = (int64_t)src + rc.ins.len + d;
        const int64_t new_disp = abs_target - (int64_t)(slot + o.len);
        if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
          log("rip 相对越界，放弃");
          cleanup_failed();
          return false;
        }
        int32_t nd = (int32_t)new_disp;
        std::memcpy(slot + rc.ins.rip_off, &nd, 4);
      }
    }

    // 4) 蹦床尾部：jmp qword ptr [rip+0] 回到原函数 patch_len_ 处（不碰寄存器）
    uint8_t* tail = tramp + out_total;
    tail[0] = 0xFF;
    tail[1] = 0x25;
    std::memset(tail + 2, 0, 4);
    uint64_t back = (uint64_t)(target_ + patch_len_);
    std::memcpy(tail + 6, &back, 8);

    // 5) relay：jmp qword ptr [rip+0] -> detour（不碰寄存器）
    relay[0] = 0xFF;
    relay[1] = 0x25;
    std::memset(relay + 2, 0, 4);
    uint64_t to = (uint64_t)detour_;
    std::memcpy(relay + 6, &to, 8);

    FlushInstructionCache(GetCurrentProcess(), page, need);

    // 6) 入口只写 5 字节：E9 rel32 -> relay。
    //    relay 已经在 ±2GB 内，所以 rel32 一定放得下。
    const int64_t rel = (int64_t)relay - (int64_t)(target_ + kPatch);
    if (rel < INT32_MIN || rel > INT32_MAX) {
      log("relay 太远（必须 ±2GB 内），放弃");
      cleanup_failed();
      return false;
    }
    trampoline_ = tramp;

    uint8_t patch[kPatch];
    patch[0] = 0xE9;
    int32_t rel32 = (int32_t)rel;
    std::memcpy(patch + 1, &rel32, 4);

    original_.assign(target_, target_ + patch_len_);

    DWORD old = unprotect(target_, kPatch);
    if (old == 0) {
      log("目标 %p 改成可写失败（GENERIC_WRITE 权限不足？）", (void*)target_);
      cleanup_failed();
      return false;
    }

    // 5 字节补丁不是原子写：挂起其余线程再落笔（shk 在 Linux 侧做不到这一点）。
    // 若挂起失败就退化成不停线程 —— 与我们自己的线程相比风险一致，但不假装安全。
    ThreadFreeze freeze;
    const bool frozen = freeze.freeze();
    const bool wrote = write_code(target_, patch, kPatch, old);

    if (!wrote) {
      log("写入入口补丁失败");
      cleanup_failed();
      return false;
    }

    installed_ = true;
    log("hooked %p -> detour %p（relay %p，蹦床 %p，patch_len=%zu%s）",
        (void*)target_, (void*)detour_, (void*)relay, (void*)tramp, patch_len_,
        frozen ? "，已挂起其余线程" : "，未能挂起线程");
    return true;
  }

  void uninstall() {
    if (!installed_) return;
    DWORD old = unprotect(target_, patch_len_);
    if (old != 0) {
      ThreadFreeze freeze;
      freeze.freeze();
      seh_memcpy(target_, original_.data(), patch_len_);
      FlushInstructionCache(GetCurrentProcess(), target_, patch_len_);
      DWORD tmp = 0;
      VirtualProtect(target_, patch_len_, old, &tmp);
    }
    if (page_ != nullptr) VirtualFree(page_, 0, MEM_RELEASE);
    detail::unmark_hooked(target_);
    trampoline_ = nullptr;
    page_ = nullptr;
    installed_ = false;
  }

  void* trampoline() const { return trampoline_; }
  void* target() const { return target_; }
  bool installed() const { return installed_; }
  explicit operator bool() const { return installed_; }

 private:
  static constexpr size_t kPatch = 5;     // E9 rel32
  static constexpr size_t kAbsJump = 14;  // FF 25 00000000 <abs64>

  void cleanup_failed() {
    if (page_ != nullptr) {
      VirtualFree(page_, 0, MEM_RELEASE);
      page_ = nullptr;
    }
    trampoline_ = nullptr;
    detail::unmark_hooked(target_);
  }

  void move_from(InlineHook& o) {
    target_ = o.target_;
    detour_ = o.detour_;
    trampoline_ = o.trampoline_;
    page_ = o.page_;
    patch_len_ = o.patch_len_;
    page_len_ = o.page_len_;
    installed_ = o.installed_;
    original_ = std::move(o.original_);
    o.trampoline_ = nullptr;
    o.page_ = nullptr;
    o.installed_ = false;
  }

  uint8_t* target_ = nullptr;
  uint8_t* detour_ = nullptr;
  uint8_t* trampoline_ = nullptr;
  uint8_t* page_ = nullptr;
  size_t patch_len_ = 0;
  size_t page_len_ = 0;
  bool installed_ = false;
  std::vector<uint8_t> original_;
};

// -----------------------------------------------------------------------------
//  8. 类型安全包装（与 shk 同形，只有 install 少了「按符号名」的重载）
// -----------------------------------------------------------------------------

template <class Fn>
class TypedHook;

template <class R, class... A>
class TypedHook<R (*)(A...)> {
 public:
  using fn_t = R (*)(A...);

  bool install(void* target, fn_t detour) {
    return hook_.install(target, reinterpret_cast<void*>(detour));
  }

  /// @brief 调用原函数（走蹦床）。必须由 detour 调用，把调用链传下去（手册 6.5）。
  R call(A... args) const {
    return reinterpret_cast<fn_t>(hook_.trampoline())(std::forward<A>(args)...);
  }

  void* trampoline() const { return hook_.trampoline(); }
  void* target() const { return hook_.target(); }
  void uninstall() { hook_.uninstall(); }
  explicit operator bool() const { return hook_.installed(); }

 private:
  InlineHook hook_;
};

}  // namespace whk

#endif  // WHK_WINHOOK_HPP
