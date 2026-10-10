// =============================================================================
#include <cstdlib>
//  shk.hpp  -  Simple Hook Kit for Linux / x86-64 / C++17
//
//  一个零依赖的单头文件内联 hook 库，专门针对「符号齐全的本地 ELF 可执行文件」
//  （Stellaris 的 stellaris 就是这种：ET_EXEC 非 PIE + 18.7 万动态符号）。
//
//  能力：
//    1. resolve()      : 按 mangled 名字解析函数地址（dlsym 优先，ELF .symtab 兜底）
//    2. InlineHook     : 12 字节绝对跳转 + 蹦床(trampoline)，可调用原函数
//    3. TypedHook<F>   : 类型安全的 hook 包装（不用手写函数指针）
//    4. VTableHook     : 直接改虚表槽（很多 C++ 调用走这里，比改 .text 更安全）
//
//  设计取舍：
//    * 指令长度解码器只覆盖「函数序言常见指令」，遇到不认识的指令会**拒绝安装**
//      而不是猜。这样最坏情况是 hook 失败，而不是把游戏打崩。
//    * 想 100% 覆盖所有 x86-64 指令，把 detail::decode 换成 Zydis/hde64 即可
//      （见 README 的 “接入外部解码器” 一节）。
//
//  License: public domain / CC0
// =============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <string>
#include <utility>
#include <vector>
#include <atomic>

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(__x86_64__)
#  error "shk currently supports x86-64 only"
#endif

namespace shk {

// -----------------------------------------------------------------------------
//  0. 小工具
// -----------------------------------------------------------------------------

inline size_t page_size() {
  static const size_t ps = (size_t)::sysconf(_SC_PAGESIZE);
  return ps;
}

inline void log(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  std::fputs("[shk] ", stderr);
  std::vfprintf(stderr, fmt, ap);
  std::fputc('\n', stderr);
  va_end(ap);
}

// 把 [addr, addr+len) 所在页全部改成 RWX。返回 false 表示失败。
inline bool unprotect(void* addr, size_t len) {
  const size_t ps = page_size();
  uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
  uintptr_t end   = ((uintptr_t)addr + len + ps - 1) & ~(uintptr_t)(ps - 1);
  return ::mprotect((void*)start, end - start,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

// 把 [addr, addr+len) 所在页改回 R-X。
inline bool protect_exec(void* addr, size_t len) {
  const size_t ps = page_size();
  uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
  uintptr_t end   = ((uintptr_t)addr + len + ps - 1) & ~(uintptr_t)(ps - 1);
  return ::mprotect((void*)start, end - start, PROT_READ | PROT_EXEC) == 0;
}

// 往任意地址写字节（自动处理页保护）。
inline bool write_code(void* dst, const void* src, size_t len) {
  if (!unprotect(dst, len)) return false;
  std::memcpy(dst, src, len);
  __builtin___clear_cache((char*)dst, (char*)dst + len);
  protect_exec(dst, len);
  return true;
}

// 在 hint 附近 (±2GB 内) 分配可写内存。
// 蹦床必须离原函数足够近，否则蹦床里被重定位的 RIP 相对 / rel32 会溢出 int32。
inline void* alloc_near(void* hint, size_t size) {
  const size_t ps = page_size();
  size = (size + ps - 1) & ~(ps - 1);
  const uintptr_t h = (uintptr_t)hint;
  const uintptr_t kStep = ps * 16;          // 64KB 一跳，省 syscall
  const uintptr_t kMax  = 0x70000000ull;    // 留足 ±2GB 余量

  for (uintptr_t d = 0; d < kMax; d += kStep) {
    uintptr_t up = h + d;
    if (up > h) {
      void* p = ::mmap((void*)(up & ~(ps - 1)), size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (p != MAP_FAILED && p != (void*)-1) return p;
    }
    if (d && h > d) {
      uintptr_t down = (h - d) & ~(ps - 1);
      void* p = ::mmap((void*)down, size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (p != MAP_FAILED && p != (void*)-1) return p;
    }
  }
  // 退而求其次：随便找地方（此时若含 RIP 相对指令会安装失败，但不会写坏内存）
  return ::mmap(nullptr, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

// -----------------------------------------------------------------------------
//  1. 符号解析
// -----------------------------------------------------------------------------

namespace detail {

// 解析主可执行文件里的 .symtab / .dynsym。
// Stellaris 是 ET_EXEC（非 PIE），st_value 就是运行时地址；
// 如果是 PIE（ET_DYN），需要加上 dl_iterate_phdr 给出的基址。
inline void* resolve_from_elf(const char* name) {
  static uintptr_t main_base = 0;
  static bool probed = false;
  if (!probed) {
    probed = true;
    ::dl_iterate_phdr(
        [](struct dl_phdr_info* info, size_t, void*) -> int {
          if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
            main_base = (uintptr_t)info->dlpi_addr;
            return 1;  // 找到主程序，停止
          }
          return 0;
        },
        nullptr);
  }

  const char* path = "/proc/self/exe";
  int fd = ::open(path, O_RDONLY);
  if (fd < 0) return nullptr;
  struct stat st {};
  if (::fstat(fd, &st) != 0) { ::close(fd); return nullptr; }
  size_t size = (size_t)st.st_size;
  void* map = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (map == MAP_FAILED) return nullptr;

  void* result = nullptr;
  auto* eh = (const Elf64_Ehdr*)map;
  if (std::memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
      eh->e_ident[EI_CLASS] == ELFCLASS64 &&
      eh->e_shoff != 0 && eh->e_shentsize == sizeof(Elf64_Shdr)) {
    const auto* sh = (const Elf64_Shdr*)((const char*)map + eh->e_shoff);
    for (unsigned s = 0; s < eh->e_shnum && !result; ++s) {
      if (sh[s].sh_type != SHT_SYMTAB && sh[s].sh_type != SHT_DYNSYM) continue;
      const auto* sym = (const Elf64_Sym*)((const char*)map + sh[s].sh_offset);
      size_t n = sh[s].sh_size / sizeof(Elf64_Sym);
      const char* str = (const char*)map + sh[sh[s].sh_link].sh_offset;
      for (size_t k = 0; k < n; ++k) {
        if (sym[k].st_name == 0) continue;
        if (std::strcmp(str + sym[k].st_name, name) != 0) continue;
        if (sym[k].st_value == 0) continue;
        result = (void*)(main_base + sym[k].st_value);
        break;
      }
    }
  }
  ::munmap(map, size);
  return result;
}

// 返回 addr 落在主可执行文件哪个符号里、还剩多少字节（不知道就返回 0）。
// 用途：防止 12 字节的补丁把邻近函数写坏。
inline size_t symbol_remaining_bytes(const void* addr) {
  static uintptr_t main_base = 0;
  static bool probed = false;
  if (!probed) {
    probed = true;
    ::dl_iterate_phdr(
        [](struct dl_phdr_info* info, size_t, void*) -> int {
          if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
            main_base = (uintptr_t)info->dlpi_addr;
            return 1;
          }
          return 0;
        },
        nullptr);
  }
  const uintptr_t want = (uintptr_t)addr;
  if (want < main_base) return 0;

  int fd = ::open("/proc/self/exe", O_RDONLY);
  if (fd < 0) return 0;
  struct stat st {};
  if (::fstat(fd, &st) != 0) { ::close(fd); return 0; }
  size_t size = (size_t)st.st_size;
  void* map = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (map == MAP_FAILED) return 0;

  size_t remain = 0;
  const auto* eh = (const Elf64_Ehdr*)map;
  if (std::memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
      eh->e_ident[EI_CLASS] == ELFCLASS64 && eh->e_shoff != 0) {
    const auto* sh = (const Elf64_Shdr*)((const char*)map + eh->e_shoff);
    for (unsigned s = 0; s < eh->e_shnum; ++s) {
      if (sh[s].sh_type != SHT_SYMTAB) continue;
      const auto* sym = (const Elf64_Sym*)((const char*)map + sh[s].sh_offset);
      size_t n = sh[s].sh_size / sizeof(Elf64_Sym);
      for (size_t k = 0; k < n; ++k) {
        if (ELF64_ST_TYPE(sym[k].st_info) != STT_FUNC) continue;
        if (sym[k].st_size == 0 || sym[k].st_value == 0) continue;
        uintptr_t lo = main_base + sym[k].st_value;
        uintptr_t hi = lo + sym[k].st_size;
        if (want >= lo && want < hi) {
          size_t r = (size_t)(hi - want);
          if (remain == 0 || r < remain) remain = r;
        }
      }
    }
  }
  ::munmap(map, size);
  return remain;
}

}  // namespace detail

// 优先用动态链接器（快、任何 so 里的符号都能找到），失败再自己解析 ELF。
inline void* resolve(const char* mangled_name) {
  void* p = ::dlsym(RTLD_DEFAULT, mangled_name);
  if (p) return p;
  return detail::resolve_from_elf(mangled_name);
}

template <class Fn>
inline Fn resolve_as(const char* mangled_name) {
  return reinterpret_cast<Fn>(resolve(mangled_name));
}

// -----------------------------------------------------------------------------
//  2. x86-64 指令长度解码（够用版）
// -----------------------------------------------------------------------------

struct insn_t {
  uint8_t len      = 0;   // 0 = 无法解码（拒绝 hook）
  int8_t  rip_off  = -1;  // RIP 相对 disp32 在指令内的偏移
  int8_t  rel_off  = -1;  // 相对跳转 disp 在指令内的偏移
  uint8_t rel_size = 0;   // 1 或 4
};

namespace detail {

inline insn_t decode(const uint8_t* p, size_t max) {
  insn_t r{};
  size_t i = 0;
  bool opsz16 = false;
  bool rexw   = false;

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
    uint8_t m   = p[i++];
    uint8_t mod = (uint8_t)(m >> 6);
    uint8_t rm  = (uint8_t)(m & 7);
    if (mod == 3) return true;
    if (rm == 4) {                                  // 有 SIB
      if (!ok(i, 1)) return false;
      uint8_t sib = p[i++];
      if ((sib & 7) == 5 && mod == 0) { if (!ok(i, 4)) return false; i += 4; }
    } else if (rm == 5 && mod == 0) {                // RIP 相对
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
    if (op == 0xC5) {                     // VEX2
      if (!ok(i, 1)) return r;
      map = (uint8_t)(p[i] & 0x1F);
      ++i;
    } else if (op == 0xC4) {              // VEX3
      if (!ok(i, 1)) return r;
      map = (uint8_t)(p[i] & 0x1F);
      i += 2;                             // 吞掉两个 VEX 字节
    } else {                              // EVEX (0x62)
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

    if (op2 >= 0x80 && op2 <= 0x8F) {                 // jcc rel32
      m = false;
      r.rel_off  = (int8_t)i;
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
        // 非法/未定义，保守拒绝
        return r;
      }
      if (imm2) { if (!ok(i, imm2)) return r; i += imm2; }
    }
    r.len = (uint8_t)i;
    return r;
  }

  // -------- 单字节 --------
  bool has_modrm = false;
  int  imm       = 0;

  if ((op >= 0x00 && op <= 0x03) || (op >= 0x08 && op <= 0x0B) ||
      (op >= 0x10 && op <= 0x13) || (op >= 0x18 && op <= 0x1B) ||
      (op >= 0x20 && op <= 0x23) || (op >= 0x28 && op <= 0x2B) ||
      (op >= 0x30 && op <= 0x33) || (op >= 0x38 && op <= 0x3B) ||
      (op >= 0x80 && op <= 0x8F) || (op >= 0xD8 && op <= 0xDF)) {
    has_modrm = true;
  }
  switch (op) {
    case 0x62: case 0x63: case 0x69: case 0x6B:          // (0x62 已在上面被 EVEX 拦截)
    case 0xC0: case 0xC1: case 0xC6: case 0xC7:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xF6: case 0xF7: case 0xFE: case 0xFF:
      has_modrm = true;
      break;
    default:
      break;
  }

  // 立即数长度
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

  // 相对跳转
  if (op >= 0x70 && op <= 0x7F) { r.rel_off = (int8_t)i; r.rel_size = 1; if (!ok(i,1)) return r; i += 1; }
  else if (op >= 0xE0 && op <= 0xE3) { r.rel_off = (int8_t)i; r.rel_size = 1; if (!ok(i,1)) return r; i += 1; }
  else if (op == 0xE8 || op == 0xE9) { r.rel_off = (int8_t)i; r.rel_size = 4; if (!ok(i,4)) return r; i += 4; }
  else if (op == 0xEB) { r.rel_off = (int8_t)i; r.rel_size = 1; if (!ok(i,1)) return r; i += 1; }

  if (has_modrm) {
    // F6/F7 只有 /0 /1 才有立即数
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

}  // namespace detail

namespace detail {

// 记录本库已经 hook 过的地址，避免重复 hook。
// 不用入口字节特征判断（合法 thunk 本身就以 E9 开头，会误判）。
inline bool mark_hooked(void* p) {
  static std::atomic<void*> table[512];
  static std::atomic<unsigned> count{0};
  unsigned n = count.load(std::memory_order_relaxed);
  for (unsigned i = 0; i < n && i < 512; ++i) {
    if (table[i].load(std::memory_order_relaxed) == p) return false;
  }
  if (n >= 512) return true;
  table[n].store(p, std::memory_order_relaxed);
  count.store(n + 1, std::memory_order_relaxed);
  return true;
}
inline void unmark_hooked(void* p) { (void)p; }

}  // namespace detail

// -----------------------------------------------------------------------------
//  3. 内联 hook
// -----------------------------------------------------------------------------

class InlineHook {
 public:
  InlineHook() = default;
  InlineHook(void* target, void* detour) { install(target, detour); }
  InlineHook(const char* symbol, void* detour) { install(symbol, detour); }

  InlineHook(const InlineHook&)            = delete;
  InlineHook& operator=(const InlineHook&) = delete;
  InlineHook(InlineHook&& o) noexcept { move_from(o); }
  InlineHook& operator=(InlineHook&& o) noexcept {
    if (this != &o) { uninstall(); move_from(o); }
    return *this;
  }
  ~InlineHook() { uninstall(); }

  bool install(const char* symbol, void* detour) {
    void* t = resolve(symbol);
    if (!t) {
      std::fprintf(stderr, "[shk] cannot resolve symbol: %s\n", symbol);
      return false;
    }
    return install(t, detour);
  }

  bool install(void* target, void* detour) {
    if (installed_) uninstall();
    target_ = (uint8_t*)target;
    detour_ = (uint8_t*)detour;

    if (!detail::mark_hooked(target_)) {
      std::fprintf(stderr, "[shk] %p 已经被本库 hook 过，拒绝重复安装\n", target_);
      return false;
    }

    // 1) 解码前 kPatch(5) 字节，确定实际要复制的长度
    size_t copied = 0;
    struct Reloc { size_t off; insn_t ins; };
    std::vector<Reloc> relocs;
    while (copied < kPatch) {
      insn_t in = detail::decode(target_ + copied, 16);
      if (in.len == 0) {
        std::fprintf(stderr,
                     "[shk] unsupported instruction at %p+%zu (bytes: %02x %02x %02x %02x %02x)\n",
                     target_, copied, target_[copied], target_[copied + 1],
                     target_[copied + 2], target_[copied + 3], target_[copied + 4]);
        return false;
      }
      relocs.push_back({copied, in});
      copied += in.len;
    }
    patch_len_ = copied;

    // 2) 安全检查：补丁不能越过本函数末尾，否则会把邻居函数写坏
    size_t sym_room = detail::symbol_remaining_bytes(target_);
    if (sym_room != 0 && sym_room < kPatch) {
      std::fprintf(stderr, "[shk] %p: 符号只剩 %zu 字节，放不下 5 字节补丁，拒绝安装\n",
                   target_, sym_room);
      return false;
    }

    // 3) 规划蹦床布局。
    //    rel8 跳转在拷贝到远处之后很可能够不到原目标（蹦床至少隔了几十 KB），
    //    所以这里**统一加宽成 rel32**，而不是放弃安装：
    //        jcc rel8 (2B, 0x70..0x7F) -> 0F 8x rel32 (6B)
    //        jmp rel8 (2B, 0xEB)       -> E9 rel32    (5B)
    //    loop/jrcxz(0xE0..0xE3) 没有 rel32 形式，保持原样，真越界才失败。
    //    注意：本函数只覆盖函数序言（>=5 字节），所以"分支目标落在被拷贝区间内部"
    //    这种情况实际不会出现（真出现的话原实现的位移算法本来也不对）。
    struct Out {
      size_t src;    // 在目标函数里的偏移
      size_t dst;    // 在蹦床里的偏移
      size_t len;    // 加宽后的长度
      uint8_t kind;  // 0=原样, 1=jcc→rel32, 2=jmp→rel32
    };
    std::vector<Out> outs;
    outs.reserve(relocs.size());
    size_t out_total = 0;
    for (const Reloc& rc : relocs) {
      const uint8_t op = target_[rc.off];
      uint8_t kind = 0;
      size_t len = rc.ins.len;
      if (rc.ins.rel_size == 1) {
        if (op >= 0x70 && op <= 0x7F) { kind = 1; len = 6; }
        else if (op == 0xEB)          { kind = 2; len = 5; }
      }
      outs.push_back({rc.off, out_total, len, kind});
      out_total += len;
    }

    // 在目标附近分配一页：[蹦床 out_total][relay kAbsJump]
    // 两处尾部都用 "FF 25 00 00 00 00 <abs64>"（jmp qword ptr [rip+0]），
    // 不破坏任何寄存器 —— 用 "mov rax,imm64; jmp rax" 会破坏 rax 而踩坑。
    const size_t need = out_total + kAbsJump + kAbsJump;
    uint8_t* page = (uint8_t*)alloc_near(target_, need);
    if (page == MAP_FAILED || page == nullptr) {
      std::fprintf(stderr, "[shk] 分配蹦床失败\n");
      detail::unmark_hooked(target_);
      return false;
    }
    page_len_ = (need + page_size() - 1) & ~(page_size() - 1);
    uint8_t* tramp = page;
    uint8_t* relay = page + out_total + kAbsJump;

    for (size_t i = 0; i < outs.size(); ++i) {
      const Out& o = outs[i];
      const Reloc& rc = relocs[i];
      uint8_t* slot = tramp + o.dst;
      const uint8_t* src = target_ + o.src;

      if (std::getenv("SHK_DEBUG")) {
        std::fprintf(stderr,
                     "[shk] reloc src=%zu dst=%zu in=%u out=%zu kind=%u "
                     "rip_off=%d rel_off=%d rel_size=%u tramp=%p\n",
                     o.src, o.dst, rc.ins.len, o.len, (unsigned)o.kind,
                     rc.ins.rip_off, rc.ins.rel_off, rc.ins.rel_size, (void*)tramp);
      }

      if (o.kind == 0) {
        std::memcpy(slot, src, rc.ins.len);
      } else {
        // 加宽：绝对目标不变，按新长度重算 disp32
        int8_t d8;
        std::memcpy(&d8, src + rc.ins.rel_off, 1);
        const int64_t abs_target = (int64_t)src + rc.ins.len + d8;
        const int64_t new_disp = abs_target - (int64_t)(slot + o.len);
        if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
          std::fprintf(stderr, "[shk] 加宽成 rel32 后仍越界，放弃\n");
          ::munmap(page, page_len_);
          detail::unmark_hooked(target_);
          return false;
        }
        int32_t nd = (int32_t)new_disp;
        if (o.kind == 1) {
          slot[0] = 0x0F;
          slot[1] = (uint8_t)(0x80 | (src[0] & 0x0F));  // jcc -> jcc rel32
          std::memcpy(slot + 2, &nd, 4);
        } else {
          slot[0] = 0xE9;                                // jmp rel8 -> jmp rel32
          std::memcpy(slot + 1, &nd, 4);
        }
        continue;  // 加宽的分支已经写完了，没有别的字段要修正
      }

      if (rc.ins.rel_off >= 0) {
        int64_t disp = 0;
        if (rc.ins.rel_size == 4) {
          int32_t d; std::memcpy(&d, src + rc.ins.rel_off, 4); disp = d;
        } else {
          int8_t d; std::memcpy(&d, src + rc.ins.rel_off, 1); disp = d;
        }
        const int64_t abs_target = (int64_t)src + rc.ins.len + disp;
        const int64_t new_disp   = abs_target - (int64_t)(slot + o.len);
        if (rc.ins.rel_size == 1) {
          // loop/jrcxz 这类没有 rel32 形式，只能保持 rel8
          if (new_disp < -128 || new_disp > 127) {
            std::fprintf(stderr, "[shk] rel8 越界（loop/jrcxz 无法加宽），放弃\n");
            ::munmap(page, page_len_);
            detail::unmark_hooked(target_);
            return false;
          }
          int8_t nd = (int8_t)new_disp;
          std::memcpy(slot + rc.ins.rel_off, &nd, 1);
        } else {
          if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
            std::fprintf(stderr, "[shk] rel32 越界，放弃\n");
            ::munmap(page, page_len_);
            detail::unmark_hooked(target_);
            return false;
          }
          int32_t nd = (int32_t)new_disp;
          std::memcpy(slot + rc.ins.rel_off, &nd, 4);
        }
      }
      if (rc.ins.rip_off >= 0) {
        int32_t d; std::memcpy(&d, src + rc.ins.rip_off, 4);
        const int64_t abs_target = (int64_t)src + rc.ins.len + d;
        const int64_t new_disp   = abs_target - (int64_t)(slot + o.len);
        if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
          std::fprintf(stderr, "[shk] rip 相对越界，放弃\n");
          ::munmap(page, page_len_);
          detail::unmark_hooked(target_);
          return false;
        }
        int32_t nd = (int32_t)new_disp;
        std::memcpy(slot + rc.ins.rip_off, &nd, 4);
      }
    }

    // 4) 蹦床尾部：jmp qword ptr [rip+0] 回到原函数 patch_len_ 处（不碰寄存器）
    uint8_t* tail = tramp + out_total;
    tail[0] = 0xFF; tail[1] = 0x25;
    std::memset(tail + 2, 0, 4);
    uint64_t back = (uint64_t)(target_ + patch_len_);
    std::memcpy(tail + 6, &back, 8);

    // 5) relay：jmp qword ptr [rip+0] -> detour（不碰寄存器）
    relay[0] = 0xFF; relay[1] = 0x25;
    std::memset(relay + 2, 0, 4);
    uint64_t to = (uint64_t)detour_;
    std::memcpy(relay + 6, &to, 8);

    __builtin___clear_cache((char*)page, (char*)page + need);
    if (::mprotect(page, page_len_, PROT_READ | PROT_EXEC) != 0) {
      std::fprintf(stderr, "[shk] mprotect 蹦床失败\n");
      ::munmap(page, page_len_);
      detail::unmark_hooked(target_);
      return false;
    }
    trampoline_ = tramp;

    // 6) 入口只写 5 字节：E9 rel32 -> relay
    int64_t rel = (int64_t)relay - (int64_t)(target_ + kPatch);
    if (rel < INT32_MIN || rel > INT32_MAX) {
      std::fprintf(stderr, "[shk] relay 太远（必须 ±2GB 内），放弃\n");
      ::munmap(page, page_len_);
      detail::unmark_hooked(target_);
      trampoline_ = nullptr;
      return false;
    }
    uint8_t patch[kPatch];
    patch[0] = 0xE9;
    int32_t rel32 = (int32_t)rel;
    std::memcpy(patch + 1, &rel32, 4);

    original_.assign(target_, target_ + patch_len_);
    if (!write_code(target_, patch, kPatch)) {
      std::fprintf(stderr, "[shk] 写入入口补丁失败\n");
      ::munmap(page, page_len_);
      detail::unmark_hooked(target_);
      trampoline_ = nullptr;
      return false;
    }

    installed_ = true;
    if (std::getenv("SHK_DEBUG")) {
      std::fprintf(stderr,
                   "[shk] hooked %p -> detour %p (relay %p), tramp %p, patch_len=%zu\n",
                   (void*)target_, (void*)detour_, (void*)relay, (void*)tramp, patch_len_);
    }
    return true;
  }

  void uninstall() {
    if (!installed_) return;
    write_code(target_, original_.data(), patch_len_);
    if (trampoline_) ::munmap(trampoline_, page_len_);
    detail::unmark_hooked(target_);
    trampoline_ = nullptr;
    installed_  = false;
  }

  void* trampoline() const { return trampoline_; }
  void* target() const { return target_; }
  bool  installed() const { return installed_; }
  explicit operator bool() const { return installed_; }

 private:
  static constexpr size_t kPatch   = 5;    // E9 rel32
  static constexpr size_t kAbsJump = 14;   // FF 25 00 00 00 00 <abs64>

  void move_from(InlineHook& o) {
    target_     = o.target_;
    detour_     = o.detour_;
    trampoline_ = o.trampoline_;
    patch_len_  = o.patch_len_;
    page_len_   = o.page_len_;
    installed_  = o.installed_;
    original_   = std::move(o.original_);
    o.trampoline_ = nullptr;
    o.installed_  = false;
  }

  uint8_t* target_     = nullptr;
  uint8_t* detour_     = nullptr;
  uint8_t* trampoline_ = nullptr;
  size_t   patch_len_  = 0;
  size_t   page_len_   = 0;
  bool     installed_  = false;
  std::vector<uint8_t> original_;
};

// -----------------------------------------------------------------------------
//  4. 类型安全包装
//       using ShootFn = void(*)(void* self, const void* data, void* target);
//       static shk::TypedHook<ShootFn> g_shoot;
//       ...
//       g_shoot.install("_ZNK16CWeaponComponent5ShootERK...", &my_shoot);
//       g_shoot.call(self, data, target);   // 调用原函数
// -----------------------------------------------------------------------------
template <class Fn>
class TypedHook;

template <class R, class... A>
class TypedHook<R (*)(A...)> {
 public:
  using fn_t = R (*)(A...);

  bool install(const char* symbol, fn_t detour) {
    return hook_.install(symbol, reinterpret_cast<void*>(detour));
  }
  bool install(void* target, fn_t detour) {
    return hook_.install(target, reinterpret_cast<void*>(detour));
  }
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

// -----------------------------------------------------------------------------
//  5. 虚表 hook（不碰 .text，最安全的做法之一）
//     void** vt = *(void***)obj;            // 对象头部的 vptr
//     shk::VTableHook h(vt, 5, &my_fn);     // 替换第 5 个虚函数
// -----------------------------------------------------------------------------
class VTableHook {
 public:
  bool install(void** vtable, size_t index, void* detour) {
    vtable_ = vtable;
    index_  = index;
    if (!vtable_ || !vtable_[index_]) return false;
    original_ = vtable_[index_];
    if (!write_entry(&vtable_[index_], detour)) return false;
    installed_ = true;
    return true;
  }
  void uninstall() {
    if (!installed_) return;
    write_entry(&vtable_[index_], original_);
    installed_ = false;
  }
  ~VTableHook() { uninstall(); }
  void* original() const { return original_; }

 private:
  static bool write_entry(void** slot, void* value) {
    if (!unprotect(slot, sizeof(void*))) return false;
    *slot = value;
    return true;
  }
  void**  vtable_   = nullptr;
  size_t  index_    = 0;
  void*   original_ = nullptr;
  bool    installed_ = false;
};

}  // namespace shk
