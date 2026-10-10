// 端到端验证：LD_PRELOAD 一个 .so，在里面 hook 游戏导出的符号。
//
// 编译： g++ -O2 -std=c++17 -shared -fPIC -o test_preload.so test_preload.cpp -ldl
// 运行： LD_PRELOAD=./test_preload.so ./fake_game
//
// ★ 重要：安装 hook 要用「全局对象的构造函数」，不要用 __attribute__((constructor))。
//   GCC 会把 __attribute__((constructor)) 排在同一个编译单元的静态初始化
//   (_GLOBAL__sub_I_...) 之前，结果全局 hook 对象会在安装完成之后又被清零。
#include "../shk.hpp"
#include <cstdio>

namespace {
using ShootFn = bool (*)(const void*, const void*, void*);
shk::TypedHook<ShootFn> g_shoot;
long g_calls = 0;

bool my_shoot(const void* self, const void* micro, void* target) {
  ++g_calls;
  bool r = g_shoot.call(self, micro, target);
  std::fprintf(stderr, "[preload] intercepted call #%ld -> %d\n", g_calls, (int)r);
  return r;
}

// 必须定义在 g_shoot 之后：同一编译单元内，动态初始化按定义顺序执行
struct Installer {
  Installer() {
    bool ok = g_shoot.install(
        "_ZNK16CWeaponComponent5ShootERK29SShipComponentMicroUpdateDataP11CTargetable",
        &my_shoot);
    std::fprintf(stderr, "[preload] hook %s (target=%p tramp=%p)\n",
                 ok ? "installed" : "FAILED", g_shoot.target(), g_shoot.trampoline());
  }
};
Installer g_installer;
}  // namespace

__attribute__((destructor)) static void report() {
  std::fprintf(stderr, "[preload] total intercepted calls = %ld\n", g_calls);
}
