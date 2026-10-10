//
//  test_winhook.cpp —— winhook.hpp 的自测，不需要开游戏。
//
//  为什么用「运行时拼出来的合成函数」而不是普通 C++ 函数
//  ------------------------------------------------------
//  shk 的自测踩过一个坑：普通 C++ 函数在 /O2 下序言形状不受控，而且同一个编译
//  单元里编译器知道目标的 clobber 集合，会把活跃变量放进 rax，于是「入口补丁
//  破坏寄存器」这类 bug 反而测不出来。
//  所以这里把**目标机器码当作数据**在运行时拼出来（VirtualAlloc RWX），
//  逐字节控制序言、分支与寄存器使用。这样能精确测到：
//
//    * 序言解码 + 5 字节补丁 + 蹦床回跳
//    * rel8 分支加宽成 rel32（jcc 与 jmp 两种）
//    * rel8 分支**目标落在被补丁字节之外**时仍然正确
//    * detour 能通过蹦床把调用链传下去
//    * 卸载后行为恢复原样
//
//  编译：见 build.bat（MSVC /std:c++20 /MT /O2）
//

#include "winhook.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) ++g_failures;
}

void log_line(const char* s) { std::printf("[whk] %s\n", s); }

// 一块可执行的合成代码
struct CodeBlock {
  uint8_t* mem = nullptr;
  size_t size = 0;

  bool alloc(const std::vector<uint8_t>& bytes) {
    size = bytes.size();
    mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, size,
                                             MEM_RESERVE | MEM_COMMIT,
                                             PAGE_EXECUTE_READWRITE));
    if (mem == nullptr) return false;
    std::memcpy(mem, bytes.data(), size);
    FlushInstructionCache(GetCurrentProcess(), mem, size);
    return true;
  }
  ~CodeBlock() {
    if (mem) VirtualFree(mem, 0, MEM_RELEASE);
  }
};

using Fn1 = int (*)(int);

// ---------------------------------------------------------------------------
// 目标 A：无分支的简单函数，序言 4 字节后就是 ret
//     mov eax, ecx      ; 8B C1
//     inc eax           ; FF C0
//     add eax, 100      ; 83 C0 64
//     ret               ; C3
//   序言解码要到 >=5 字节，所以会一次吃完 mov+inc+add（2+2+3=7）。
//   结果：f(1)=1+1+100=102，f(5)=106，f(-1)=100   ← 注意 inc 在 add 之前
// ---------------------------------------------------------------------------
std::vector<uint8_t> code_a() { return {0x8B, 0xC1, 0xFF, 0xC0, 0x83, 0xC0, 0x64, 0xC3}; }

// ---------------------------------------------------------------------------
// 目标 B：序言里有 jcc rel8（正数走 +1，否则走 -1）
//     test ecx, ecx        ; 85 C9          off 0  (2B)
//     jle  L_neg           ; 7E 06          off 2  (2B) -> target = 2+2+6 = off 10
//     mov  eax, 1          ; B8 01 00 00 00 off 4  (5B)
//     ret                  ; C3             off 9
//   L_neg:
//     mov  eax, -1         ; B8 FF FF FF FF off 10 (5B)
//     ret                  ; C3             off 15
//   补丁长度会是 9（test+jle+mov），rel8 的目标 off 10 落在**补丁之外**。
// ---------------------------------------------------------------------------
std::vector<uint8_t> code_b() {
  return {0x85, 0xC9,
          0x7E, 0x06,
          0xB8, 0x01, 0x00, 0x00, 0x00,
          0xC3,
          0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
          0xC3};
}

// ---------------------------------------------------------------------------
// 目标 C：序言里有 jmp rel8，跳过一整条 mov（死代码）
//     jmp  L_end           ; EB 05          off 0  (2B) -> target = 1+1+5 = off 7
//     mov  eax, 7          ; B8 07 00 00 00 off 2  (5B) 死代码
//   L_end:
//     mov  eax, 42         ; B8 2A 00 00 00 off 7  (5B)
//     ret                  ; C3             off 12
//   rel8 的 disp 必须正好跨过整条 5 字节 mov；写成 03 会跳进 mov 的中间，
//   那本身就是坏代码（实测会 AV），不是被测对象的问题。
//   补丁长度 = 2 + 5 = 7，而 jmp 的目标 off 7 正好落在补丁边界上（边界用例）。
// ---------------------------------------------------------------------------
std::vector<uint8_t> code_c() {
  return {0xEB, 0x05,
          0xB8, 0x07, 0x00, 0x00, 0x00,
          0xB8, 0x2A, 0x00, 0x00, 0x00,
          0xC3};
}

}  // namespace

int main() {
  // 不缓冲：这个自测会在出错时硬崩（AV），缓冲的输出会连同进程一起丢掉，
  // 那样就只能看到"没有任何输出"，定位不了是哪一步行。
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::setvbuf(stderr, nullptr, _IONBF, 0);

  whk::set_logger(&log_line);

  std::printf("=== winhook 自测 ===\n");
  std::printf("镜像基址 = %p\n", (void*)whk::image_base());

  // ---------------------------------------------------------------------
  std::printf("\n[1] 基础环境\n");
  check(whk::image_base() != 0, "image_base 非空");
  {
    int probe = 0x1234;
    int out = 0;
    check(whk::safe_read(&out, &probe, sizeof out) && out == 0x1234, "safe_read 可读地址");
    check(!whk::safe_read(&out, (void*)0x1, sizeof out), "safe_read 拒绝空指针区");
    check(whk::is_mapped((uintptr_t)&probe), "is_mapped 认得自己的栈");
    void* near_mem = whk::alloc_near(&probe, 0x1000);
    check(near_mem != nullptr, "alloc_near 分配成功");
    if (near_mem) {
      const int64_t delta = (int64_t)near_mem - (int64_t)&probe;
      check(delta > INT32_MIN && delta < INT32_MAX, "alloc_near 落在 ±2GB 内");
      VirtualFree(near_mem, 0, MEM_RELEASE);
    }
  }

  // ---------------------------------------------------------------------
  std::printf("\n[2] 目标 A：基本 hook + 蹦床回跳\n");
  CodeBlock a;
  check(a.alloc(code_a()), "合成代码 A 分配成功");
  if (a.mem == nullptr) return 2;

  Fn1 fn_a = reinterpret_cast<Fn1>(a.mem);
  check(fn_a(1) == 102, "hook 前：fn_a(1) == 102");

  static int g_detour_calls = 0;
  static Fn1 g_a_orig = nullptr;
  static int g_a_saw_arg = -1;

  struct DetourA {
    static int fn(int x) {
      ++g_detour_calls;
      g_a_saw_arg = x;
      return g_a_orig(x) + 1000;  // 通过蹦床调原函数
    }
  };

  whk::TypedHook<Fn1> hook_a;
  const bool ok_a = hook_a.install(a.mem, &DetourA::fn);
  check(ok_a, "目标 A 安装成功");
  if (!ok_a) return 3;

  g_a_orig = reinterpret_cast<Fn1>(hook_a.trampoline());
  const int r_a = fn_a(5);
  check(g_detour_calls == 1, "detour 被调用");
  check(g_a_saw_arg == 5, "detour 收到正确参数");
  // f(5) = 5 + 1 + 100 = 106；detour 再 +1000
  check(r_a == 1106, "detour 经蹦床调原函数得到 106，再 +1000 == 1106");

  // 蹦床本身必须与原函数行为一致（不能因为重定位写坏）
  check(g_a_orig(1) == 102, "蹦床直接调用 == 原函数结果（102）");
  check(g_a_orig(-1) == 100, "蹦床处理负数（-1 -> 100）");
  check(g_a_orig(-200) == -99, "蹦床处理更小的负数（-200 -> -99）");

  // ---------------------------------------------------------------------
  std::printf("\n[3] 目标 B：序言里的 jcc rel8 加宽\n");
  CodeBlock b;
  check(b.alloc(code_b()), "合成代码 B 分配成功");
  if (b.mem == nullptr) return 4;

  Fn1 fn_b = reinterpret_cast<Fn1>(b.mem);
  check(fn_b(1) == 1, "hook 前：fn_b(1) == 1");
  check(fn_b(-1) == -1, "hook 前：fn_b(-1) == -1");

  static Fn1 g_b_orig = nullptr;
  struct DetourB {
    static int fn(int x) { return g_b_orig(x); }  // 纯透传
  };

  whk::TypedHook<Fn1> hook_b;
  const bool ok_b = hook_b.install(b.mem, &DetourB::fn);
  check(ok_b, "目标 B（含 jcc rel8）安装成功 —— 验证加宽生效");
  if (ok_b) {
    g_b_orig = reinterpret_cast<Fn1>(hook_b.trampoline());
    check(fn_b(1) == 1, "加宽后：正数分支仍返回 1");
    check(fn_b(-1) == -1, "加宽后：负数分支仍返回 -1（rel8 目标在被补丁字节之外）");
    check(fn_b(0) == -1, "加宽后：0 走 jle 分支");
    check(g_b_orig(1) == 1 && g_b_orig(-1) == -1, "蹦床对两个分支都正确");
  }

  // ---------------------------------------------------------------------
  std::printf("\n[4] 目标 C：序言里的 jmp rel8 加宽\n");
  CodeBlock c;
  check(c.alloc(code_c()), "合成代码 C 分配成功");
  if (c.mem == nullptr) return 5;

  Fn1 fn_c = reinterpret_cast<Fn1>(c.mem);
  check(fn_c(0) == 42, "hook 前：fn_c 返回 42");

  static Fn1 g_c_orig = nullptr;
  struct DetourC {
    static int fn(int x) { return g_c_orig(x); }
  };
  whk::TypedHook<Fn1> hook_c;
  const bool ok_c = hook_c.install(c.mem, &DetourC::fn);
  check(ok_c, "目标 C（含 jmp rel8）安装成功");
  if (ok_c) {
    g_c_orig = reinterpret_cast<Fn1>(hook_c.trampoline());
    check(fn_c(0) == 42, "加宽后：仍然返回 42（jmp 跳过死代码）");
    check(g_c_orig(0) == 42, "蹦床返回 42（没有走进死代码的 7）");
  }

  // ---------------------------------------------------------------------
  std::printf("\n[5] 重复安装必须被拒绝\n");
  whk::TypedHook<Fn1> hook_a2;
  check(!hook_a2.install(a.mem, &DetourA::fn), "同一地址第二次安装被拒绝");

  // ---------------------------------------------------------------------
  std::printf("\n[6] 拒绝坏目标\n");
  {
    whk::TypedHook<Fn1> bad;
    check(!bad.install(nullptr, &DetourA::fn), "空指针目标被拒绝");
    check(!bad.install((void*)0x1234, &DetourA::fn), "不可读地址被拒绝");
  }

  // ---------------------------------------------------------------------
  std::printf("\n[7] 卸载后恢复原状\n");
  hook_a.uninstall();
  g_detour_calls = 0;
  check(fn_a(1) == 102, "卸载后 fn_a(1) 回到 102");
  check(g_detour_calls == 0, "卸载后 detour 不再被调用");
  // 卸载后应可以重新安装（这一条在 shk 里是坏的：unmark 是空操作）
  check(hook_a2.install(a.mem, &DetourA::fn), "卸载后可重新安装（撤销登记有效）");
  if (hook_a2) {
    g_a_orig = reinterpret_cast<Fn1>(hook_a2.trampoline());
    g_detour_calls = 0;
    check(fn_a(2) == 1103, "重新安装后 detour 生效（f(2)=103，再 +1000）");
    hook_a2.uninstall();
  }

  std::printf("\n=== 结果：%s（失败 %d 项）===\n",
              g_failures == 0 ? "全部通过" : "有失败", g_failures);
  return g_failures == 0 ? 0 : 1;
}
