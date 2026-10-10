// 测试 shk.hpp
//   1) 功能测试：hook 普通函数 / RIP 相对寻址函数 / 以 jmp 开头的函数
//   2) 解码器压力测试：拿真实的 stellaris 二进制，遍历所有 STT_FUNC 符号，
//      统计「函数序言前 12 字节能否被完整解码」
//
// 编译： g++ -O2 -std=c++17 -no-pie -o test_shk test_shk.cpp -ldl
// 运行： ./test_shk [stellaris 路径]

#include "shk.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>

// ---------------------------------------------------------------------------
// 被测函数
// ---------------------------------------------------------------------------

volatile int g_sink = 0;

// 典型的 push rbp / sub rsp 序言
__attribute__((noinline)) int target_add(int a, int b) {
  g_sink += 1;
  return a + b;
}

// 序言里有 RIP 相对访存（-no-pie 下是绝对disp，-fPIC 下是 RIP 相对）
static const char g_table[64] = "0123456789abcdef";
__attribute__((noinline)) int target_rip(int i) {
  return g_table[i & 15] - '0' + g_sink;
}

// 入口就是一条 jmp（模拟链接器 thunk / 已被折叠的函数）：运行时造一个 stub
__attribute__((noinline)) int target_real(int a) { return a * 3 + g_sink; }
static int (*make_jmp_stub(int (*fn)(int)))(int) {
  // 注意：E9 是 rel32，stub 必须落在目标 ±2GB 内，否则 rel32 会溢出
  uint8_t* m = (uint8_t*)shk::alloc_near((void*)fn, 64);
  // E9 rel32 | B8 00000000 (mov eax,0) | C3 (ret) | nop 填充
  m[0] = 0xE9;
  int32_t rel = (int32_t)((int64_t)((uint8_t*)fn - (m + 5)));
  std::memcpy(m + 1, &rel, 4);
  m[5] = 0xB8;
  std::memset(m + 6, 0, 4);
  m[10] = 0xC3;
  std::memset(m + 11, 0x90, 16);
  ::mprotect(m, 64, PROT_READ | PROT_EXEC);
  return (int (*)(int))m;
}

// ---------------------------------------------------------------------------
// 测试 1：功能
// ---------------------------------------------------------------------------

static int (*g_orig_add)(int, int) = nullptr;
static int (*g_orig_rip)(int)      = nullptr;
static int (*g_orig_jmp)(int)      = nullptr;

static int hits_add = 0, hits_rip = 0, hits_jmp = 0;

static int detour_add(int a, int b) { ++hits_add; return g_orig_add(a, b) + 100; }
static int detour_rip(int i)        { ++hits_rip; return g_orig_rip(i) + 1000; }
static int detour_jmp(int a)        { ++hits_jmp; return g_orig_jmp(a) + 10000; }

static int test_functional() {
  int failures = 0;

  shk::InlineHook h_add, h_rip, h_jmp;

  if (!h_add.install((void*)&target_add, (void*)&detour_add)) {
    std::printf("  [FAIL] hook target_add 安装失败\n");
    ++failures;
  } else {
    g_orig_add = (int (*)(int, int))h_add.trampoline();
    int r = target_add(2, 3);
    if (hits_add == 1 && r == 105) {
      std::printf("  [ OK ] target_add: detour + trampoline 正常 (r=%d)\n", r);
    } else {
      std::printf("  [FAIL] target_add: r=%d hits=%d\n", r, hits_add);
      ++failures;
    }
  }

  if (!h_rip.install((void*)&target_rip, (void*)&detour_rip)) {
    std::printf("  [FAIL] hook target_rip 安装失败\n");
    ++failures;
  } else {
    g_orig_rip = (int (*)(int))h_rip.trampoline();
    int r = target_rip(3);
    if (hits_rip == 1 && r == g_sink + 3 + 1000) {
      std::printf("  [ OK ] target_rip: RIP 相对序言正常 (r=%d)\n", r);
    } else {
      std::printf("  [FAIL] target_rip: r=%d hits=%d\n", r, hits_rip);
      ++failures;
    }
  }

  auto* stub = make_jmp_stub(&target_real);
  std::fprintf(stderr, "[test] stub=%p, installing...\n", (void*)stub);
  std::fflush(stderr);
  if (!h_jmp.install((void*)stub, (void*)&detour_jmp)) {
    std::printf("  [FAIL] hook target_jmp 安装失败\n");
    ++failures;
  } else {
    g_orig_jmp = (int (*)(int))h_jmp.trampoline();
    int r = stub(4);
    if (hits_jmp == 1 && r == 12 + g_sink + 10000) {
      std::printf("  [ OK ] target_jmp: 入口 rel32 跳转重定位正常 (r=%d)\n", r);
    } else {
      std::printf("  [FAIL] target_jmp: r=%d hits=%d\n", r, hits_jmp);
      ++failures;
    }
  }

  // 卸载后必须恢复原状
  h_add.uninstall();
  int r = target_add(2, 3);
  if (hits_add == 1 && r == 5) {
    std::printf("  [ OK ] uninstall 恢复原函数 (r=%d)\n", r);
  } else {
    std::printf("  [FAIL] uninstall 未恢复: r=%d hits=%d\n", r, hits_add);
    ++failures;
  }
  return failures;
}

// ---------------------------------------------------------------------------
// 测试 2：真实二进制解码器压力测试
// ---------------------------------------------------------------------------

static int test_decoder_sweep(const char* path) {
  int fd = ::open(path, O_RDONLY);
  if (fd < 0) { std::printf("  (跳过：无法打开 %s)\n", path); return 0; }
  struct stat st {};
  ::fstat(fd, &st);
  size_t size = (size_t)st.st_size;
  void* map = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (map == MAP_FAILED) { std::printf("  (跳过：mmap 失败)\n"); return 0; }

  const auto* eh = (const Elf64_Ehdr*)map;
  const auto* sh = (const Elf64_Shdr*)((const char*)map + eh->e_shoff);
  const Elf64_Sym* sym = nullptr;
  size_t nsym = 0;
  const char* str = nullptr;
  for (unsigned i = 0; i < eh->e_shnum; ++i) {
    if (sh[i].sh_type == SHT_SYMTAB) {
      sym = (const Elf64_Sym*)((const char*)map + sh[i].sh_offset);
      nsym = sh[i].sh_size / sizeof(Elf64_Sym);
      str = (const char*)map + sh[sh[i].sh_link].sh_offset;
      break;
    }
  }
  if (!sym) { std::printf("  (跳过：没有 .symtab)\n"); ::munmap(map, size); return 0; }

  size_t total = 0, bad = 0, rip = 0, rel = 0;
  std::map<uint8_t, int> bad_first_op;
  int shown_names = 0;
  for (size_t i = 0; i < nsym; ++i) {
    if (ELF64_ST_TYPE(sym[i].st_info) != STT_FUNC) continue;
    if (sym[i].st_value == 0 || sym[i].st_size == 0) continue;
    const uint8_t* code = (const uint8_t*)((const char*)map + sym[i].st_value);
    if (sym[i].st_value + sym[i].st_size > size) continue;
    ++total;
    size_t copied = 0;
    while (copied < 12) {
      shk::insn_t in = shk::detail::decode(code + copied, 16);
      if (in.len == 0) {
        ++bad;
        bad_first_op[code[0]]++;
        if (shown_names < 5) {
          std::printf("    解码失败: %s @ %p :", str + sym[i].st_name, (const void*)code);
          for (int k = 0; k < 16; ++k) std::printf(" %02x", code[k]);
          std::printf("\n");
          ++shown_names;
        }
        break;
      }
      if (in.rip_off >= 0) ++rip;
      if (in.rel_off >= 0) ++rel;
      copied += in.len;
    }
  }
  std::printf("  扫描函数数: %zu\n", total);
  std::printf("  序言前 12 字节解码失败: %zu (%.3f%%)\n", bad, 100.0 * bad / (double)total);
  std::printf("  含 RIP 相对寻址的指令: %zu, 含相对跳转: %zu\n", rip, rel);
  if (bad) {
    std::printf("  失败样本首字节分布(bad 数 >= 3 时列出):\n");
    int shown = 0;
    for (auto& kv : bad_first_op) {
      if (kv.second >= 3 && shown < 15) {
        std::printf("    opcode 0x%02x : %d\n", kv.first, kv.second);
        ++shown;
      }
    }
  }
  ::munmap(map, size);
  return bad == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
  std::printf("== 1. 功能测试 ==\n");
  int fails = test_functional();

  std::printf("== 2. 解码器压力测试 ==\n");
  const char* game = argc > 1 ? argv[1]
                              : "/home/koishi/added_disk/SteamLibrary/steamapps/"
                                "common/Stellaris/stellaris";
  int sweep = test_decoder_sweep(game);

  std::printf("\n结果: 功能失败 %d 项, 解码器扫描%s\n", fails, sweep ? "有失败" : "通过");
  return (fails == 0 && sweep == 0) ? 0 : 1;
}
