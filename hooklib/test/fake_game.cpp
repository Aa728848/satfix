// 假的“游戏”进程：导出一个和 Stellaris 同名的符号，用来端到端验证
// LD_PRELOAD + dlsym 这条路径。
// 编译： g++ -O2 -std=c++17 -no-pie -rdynamic -o fake_game fake_game.cpp
#include <cstdio>

volatile int g_fake_sink = 0;

// noipa 很关键：告诉编译器不要用「我知道这个函数的 clobber 集合」去优化调用点。
// 真实游戏里调用方和目标不在同一个编译单元，本来就没有这种假设；
// 但测试里都在一个 TU，不加 noipa 的话 main 的循环计数器可能被塞进某个
// caller-saved 寄存器，然后被我们的 detour（一个普通 C 函数）覆盖，导致死循环。
__attribute__((noinline, noipa, used, visibility("default")))
bool fake_shoot(const void* self, const void* micro, void* target) {
  (void)self; (void)micro; (void)target;
  g_fake_sink += 1;
  return true;
}

asm(".globl _ZNK16CWeaponComponent5ShootERK29SShipComponentMicroUpdateDataP11CTargetable\n"
    ".set   _ZNK16CWeaponComponent5ShootERK29SShipComponentMicroUpdateDataP11CTargetable,"
    "_Z10fake_shootPKvS0_Pv\n");

int main() {
  for (int i = 0; i < 5; ++i) fake_shoot(nullptr, nullptr, nullptr);
  std::printf("fake_game: shoot called 5 times\n");
  return 0;
}
