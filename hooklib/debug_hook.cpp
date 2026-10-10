#include "shk.hpp"
#include <cstdio>

volatile int g_sink = 0;
static const char g_table[64] = "0123456789abcdef";

__attribute__((noinline)) int target_add(int a, int b) { g_sink += 1; return a + b; }
__attribute__((noinline)) int target_rip(int i) { return g_table[i & 15] - '0' + g_sink; }

static int (*g_orig_add)(int, int) = nullptr;
static int (*g_orig_rip)(int) = nullptr;

static int detour_add(int a, int b) { return g_orig_add(a, b) + 100; }
static int detour_rip(int i) { return g_orig_rip(i) + 1000; }

static void dump(const char* tag, const void* p, int n) {
  std::printf("%-10s @%p :", tag, p);
  const unsigned char* b = (const unsigned char*)p;
  for (int i = 0; i < n; ++i) std::printf(" %02x", b[i]);
  std::printf("\n");
}

int main() {
  std::printf("g_table=%p g_sink=%p\n", (void*)g_table, (void*)&g_sink);
  std::printf("target_add=%p target_rip=%p\n", (void*)&target_add, (void*)&target_rip);

  shk::InlineHook h1;
  std::printf("install add -> %d\n", (int)h1.install((void*)&target_add, (void*)&detour_add));
  g_orig_add = (int (*)(int, int))h1.trampoline();
  dump("orig", (void*)&target_add, 16);
  dump("tramp", h1.trampoline(), 24);
  std::printf("before: g_sink=%d\n", (int)g_sink);
  int r1 = target_add(2, 3);
  std::printf("call target_add(2,3) = %d\n", r1);
  std::printf("after : g_sink=%d\n", (int)g_sink);

  shk::InlineHook h2;
  std::printf("install rip -> %d\n", (int)h2.install((void*)&target_rip, (void*)&detour_rip));
  g_orig_rip = (int (*)(int))h2.trampoline();
  dump("orig", (void*)&target_rip, 20);
  dump("tramp", h2.trampoline(), 32);
  std::printf("before rip: g_sink=%d\n", (int)g_sink);
  std::printf("tramp2=%p g_orig_rip=%p\n", h2.trampoline(), (void*)g_orig_rip);
  for (int i = 0; i < 16; ++i) std::printf(" tramp(%2d)=%3d", i, g_orig_rip(i));
  std::printf("\n");
  int r2 = g_orig_rip(3);
  std::printf("direct orig(3)=%d (g_sink=%d)\n", r2, (int)g_sink);
  int r3 = target_rip(3);
  std::printf("call target_rip(3) = %d (g_sink=%d)\n", r3, (int)g_sink);
  std::fflush(stdout);
  return 0;
}
