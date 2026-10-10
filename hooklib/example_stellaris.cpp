// =============================================================================
//  在 Stellaris (Linux) 上使用 shk 的示例
//
//  构建：
//    g++ -O2 -std=c++17 -shared -fPIC -o mystellaris_hook.so example_stellaris.cpp -ldl
//
//  运行（game 目录下）：
//    LD_PRELOAD=$PWD/mystellaris_hook.so ./stellaris
//  或者写进启动脚本：
//    exec env LD_PRELOAD=/path/mystellaris_hook.so ./stellaris "$@"
//
//  要点：stellaris 是 **非 PIE** 的 ET_EXEC（基址固定 0x400000），
//  且带了 18.7 万个动态符号，所以
//    * 按 mangled 名字 hook：直接可用，不需要算基址；
//    * 也可以直接用 nm 里的绝对地址（仅对本 build 有效）。
// =============================================================================

#include "shk.hpp"

#include <cstdio>

// ---------------------------------------------------------------------------
// 1) 按 mangled 名字 hook：CWeaponComponent::Shoot
//    符号：_ZNK16CWeaponComponent5ShootERK29SShipComponentMicroUpdateDataP11CTargetable
//         bool CWeaponComponent::Shoot(SShipComponentMicroUpdateData const&, CTargetable*) const
//    我们不需要完整的类定义，把 this/参数当 void* 转发即可。
// ---------------------------------------------------------------------------
namespace {

using ShootFn = bool (*)(const void* self, const void* micro, void* target);
shk::TypedHook<ShootFn> g_shoot;

long g_shoot_calls = 0;

bool my_shoot(const void* self, const void* micro, void* target) {
  ++g_shoot_calls;
  // 想“干掉这次开火”就 return false；想放行就调原函数。
  bool fired = g_shoot.call(self, micro, target);
  if (fired && (g_shoot_calls % 1000) == 0) {
    std::fprintf(stderr, "[hook] Shoot calls = %ld\n", g_shoot_calls);
  }
  return fired;
}

// ---------------------------------------------------------------------------
// 2) 不知道完整 mangled 名 / 名字太长时，直接用绝对地址（本 build 专用）
//    CFleet::CalculateModifier(...)  = 0x2599960
//    CFleet::UpdateFleetSize()       = 0x25a4860
//    地址来自： nm stellaris | grep ...    （非 PIE，运行时同值）
// ---------------------------------------------------------------------------
constexpr uintptr_t kCFleetCalculateModifier = 0x2599960;
constexpr uintptr_t kCFleetUpdateFleetSize   = 0x25a4860;

using CalcModFn    = void (*)(void* fleet, void* modifier_node);
using UpdateSizeFn = void (*)(void* fleet);

shk::TypedHook<UpdateSizeFn> g_update_size;

long g_update_size_calls = 0;
void my_update_size(void* fleet) {
  ++g_update_size_calls;
  // fleet+0x1268 就是 force disparity 用的舰队规模
  int64_t size1268 = 0;
  if (fleet) std::memcpy(&size1268, (const char*)fleet + 0x1268, 8);
  if ((g_update_size_calls % 5000) == 0) {
    std::fprintf(stderr, "[hook] UpdateFleetSize #%ld, +0x1268=%lld (%.3f)\n",
                 g_update_size_calls, (long long)size1268,
                 (double)size1268 / 100000.0);
  }
  g_update_size.call(fleet);
}

}  // namespace

static void install_hooks() {
  std::fprintf(stderr, "[hook] hello from %s\n", __FILE__);

  if (g_shoot.install(
          "_ZNK16CWeaponComponent5ShootERK29SShipComponentMicroUpdateDataP11CTargetable",
          &my_shoot)) {
    std::fprintf(stderr, "[hook] CWeaponComponent::Shoot hooked\n");
  } else {
    std::fprintf(stderr, "[hook] failed to hook CWeaponComponent::Shoot\n");
  }

  // 用地址 hook（不需要符号名）
  if (g_update_size.install((void*)kCFleetUpdateFleetSize, &my_update_size)) {
    std::fprintf(stderr, "[hook] CFleet::UpdateFleetSize hooked at 0x%lx\n",
                 (unsigned long)kCFleetUpdateFleetSize);
  }

  // 只读一下地址，不做 hook，确认解析没问题
  void* calc = shk::resolve(
      "_ZN6CFleet17CalculateModifierERN13NModifierNode13CModifierNodeI9CModifier"
      "21EModifierNodeCategoryLS3_23ENS0_13SDependenciesIS3_JNS1_IS2_S3_LS3_3ENS4_"
      "IS3_JEEEEENS1_IS2_S3_LS3_4ES5_EENS1_IS2_S3_LS3_13ES5_EENS1_IS2_S3_LS3_15ES5_"
      "EENS1_IS2_S3_LS3_9ES5_EENS1_IS2_S3_LS3_2ENS4_IS3_JNS1_IS2_S3_LS3_10ES5_EENS1_"
      "IS2_S3_LS3_25ES5_EENS1_IS2_S3_LS3_33ES5_EEEEEEENS1_IS2_S3_LS3_6ES5_EENS1_IS2_"
      "S3_LS3_5ES5_EENS1_IS2_S3_LS3_29ENS4_IS3_JS7_S8_NS1_IS2_S3_LS3_24ES5_EESH_SG_"
      "SF_NS1_IS2_S3_LS3_0ES5_EENS1_IS2_S3_LS3_32ES5_EEEEEEENS1_IS2_S3_LS3_26ES5_EEEEEEE");
  std::fprintf(stderr, "[hook] resolve(CalculateModifier) = %p (期望 0x%lx)\n",
               calc, (unsigned long)kCFleetCalculateModifier);
}

// ★ 必须用全局对象的构造函数来安装，不要用 __attribute__((constructor))。
//   GCC 会把 __attribute__((constructor)) 排在同一个编译单元的静态初始化
//   (_GLOBAL__sub_I_...) 之前，结果全局 hook 对象会在安装完成之后又被清零，
//   表现是「hook 装上了，但 detour 里看到的 trampoline 是 nullptr」。
//
//   这里 g_auto_install 定义在所有 hook 对象之后，
//   同一编译单元内动态初始化按定义顺序执行，所以顺序是对的。
namespace {
struct AutoInstall {
  AutoInstall() { install_hooks(); }
};
AutoInstall g_auto_install;
}  // namespace
