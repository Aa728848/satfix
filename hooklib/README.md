# shk —— Linux x86-64 零依赖单头文件 Hook 库

面向「带符号的本地 ELF 可执行文件」（例如 Linux 版 Stellaris，未 strip、含 18.7 万+ 动态符号）编写的极简 C++17 内联 / 虚表 hook 库。

```text
hooklib/
├── shk.hpp                 库本体（单头文件，C++17，无第三方依赖）
├── example_stellaris.cpp   拦截 Stellaris CWeaponComponent::Shoot / UpdateFleetSize 示例
├── test_shk.cpp            功能自测 + 对真实 stellaris 的全量函数解码扫描
├── debug_hook.cpp          排查工具（打印蹦床字节）
└── test/
    ├── fake_game.cpp       模拟目标进程（导出同名符号）
    └── test_preload.cpp    端到端 LD_PRELOAD 拦截验证
```

---

## 1. 快速上手

```bash
# 编译自定义 hook 共享库
g++ -O2 -std=c++17 -shared -fPIC -o my_hook.so my_hook.cpp -ldl

# 启动目标进程
LD_PRELOAD="$PWD/my_hook.so" ./stellaris
```

三步完成一个函数拦截：

```cpp
#include "shk.hpp"

// 1) 用不依赖类定义的原生函数指针描述目标签名（this/类指针用 void*）
using ShootFn = bool (*)(const void* self, const void* micro, void* target);
shk::TypedHook<ShootFn> g_shoot;

// 2) 编写 detour；调用原函数使用 g_shoot.call(...)
bool my_shoot(const void* self, const void* micro, void* target) {
    return g_shoot.call(self, micro, target);
}

// 3) 用全局对象构造函数安装（切勿用 __attribute__((constructor))，见 §3.1）
struct Installer {
    Installer() { g_shoot.install("_ZNK16CWeaponComponent5Shoot...", &my_shoot); }
};
Installer g_installer;
```

> **关于 PIE 与运行时地址**：实测 Linux 版 Stellaris 为 PIE（`ET_DYN`），运行时加载基址随机化。请优先使用**符号名安装**——`shk::resolve` 会先调 `dlsym`，失败再解析 `/proc/self/exe` 符号表并自动叠加加载基址。**切勿把 `nm` 静态输出的地址直接硬编码为运行时地址。**

---

## 2. API 速查

| 接口 | 作用 |
| --- | --- |
| `shk::resolve(name)` | 按 mangled 符号名解析运行时地址：先 `dlsym(RTLD_DEFAULT)`，失败再解析 `/proc/self/exe` 的 `.symtab`/`.dynsym`（自动处理 PIE 基址） |
| `shk::resolve_as<Fn>(name)` | 同上，并转换为目标函数指针类型 |
| `shk::write_code(dst, src, len)` | 修改代码段内存（自动 `mprotect` 为 `RWX`，写完恢复 `R-X`） |
| `shk::InlineHook` | 底层钩子：`install(target/symbol, detour)`、`uninstall()`、`trampoline()`、`target()` |
| `shk::TypedHook<Fn>` | 类型安全包装，提供 `call(args...)` 转发至原函数 |
| `shk::VTableHook` | 替换虚表槽：`install(vtable, index, detour)`，不修改 `.text` |
| `shk::alloc_near(hint, size)` | 在 `hint` 的 ±1.75 GB 范围内用 `MAP_FIXED_NOREPLACE` 申请临近页 |

---

## 3. 两个必知的工程坑

### 3.1 不要使用 `__attribute__((constructor))` 安装钩子

GCC 会将 `__attribute__((constructor))` 排在同一编译单元的 C++ 全局对象构造函数（`_GLOBAL__sub_I_...`）**之前**执行。若在 constructor 中调用 `g_shoot.install(...)`，紧接着的全局初始化会把 `g_shoot` 重新零初始化、清掉蹦床指针，导致首次调用原函数即空指针崩溃。

**正确做法**：将所有 `TypedHook` 全局变量声明在前，再定义一个排在最后的全局结构体，在其构造函数中统一调用 `install(...)`（同一编译单元严格按声明顺序初始化）。

### 3.2 入口补丁不能破坏任何寄存器

常见的 12 字节跳转 `mov rax, imm64; jmp rax` 会破坏 `rax`。在同编译单元调用或开启 LTO 的目标二进制里，编译器可能掌握被调函数的实际寄存器破坏集，把活跃变量放在 `rax` 中跨调用复用，导致循环死锁或崩溃。

`shk` 在目标 ±1.75 GB 范围内分配临近页，构造两跳结构：

```text
原函数入口 : E9 rel32 -> relay                          (仅 5 字节，零寄存器破坏)
[relay]   : FF 25 00000000 <detour 64位绝对地址>         (jmp qword ptr [rip+0])
[蹦床]     : 重定位后的原序言指令副本 + FF 25 00000000 <原函数+N>
```

（同样原因，编写离线测试假游戏时需给目标函数加 `__attribute__((noipa))`，防止编译器基于过程间分析优化调用点。）

---

## 4. 核心设计细节

- **保守指令长度解码器**：覆盖常见 x86-64 函数序言指令，遇未知编码立即拒绝安装而不盲目覆盖。对真实 `stellaris` 的 139,452 个 `STT_FUNC` 符号做前 12 字节扫描实测失败数为 `0`。如需完整覆盖全部 x86-64 指令，替换 `shk::detail::decode`（接口仅 `insn_t{len, rip_off, rel_off, rel_size}`）接入 Zydis / hde64 即可。
- **rel8 → rel32 跳转加宽**：将序言拷贝到远端蹦床时，短跳转往往超出 ±128 B 范围（例如 `CFixedPoint::SafeSqrt(long long)` 的 `push rax; test rdi, rdi; jle rel8`）。蹦床生成器采用两遍布局，自动加宽短跳并重算后续所有指令偏移与 RIP 相对寻址：
  - `jcc rel8`（`0x70..0x7F`，2 字节）→ `0F 8x rel32`（6 字节）；
  - `jmp rel8`（`0xEB`，2 字节）→ `E9 rel32`（5 字节）；
  - `loop` / `jrcxz`（`0xE0..0xE3`）无 rel32 形式，越界则拒绝安装。
- **符号尺寸保护**：解析 `/proc/self/exe` 的 `.symtab`，若目标符号尺寸 < 5 字节则拒绝安装，避免越界破坏相邻函数。
- **重复安装保护**：使用原子地址表记录已安装目标，而不依赖「入口字节是否为 `E9`」（避免误判合法的链接器 thunk）。

---

## 5. 已知限制与选型参考

### 已知限制

- 仅支持 **Linux x86-64**（编译期 `#error` 保护）。
- **安装/卸载非线程安全**：未实现线程挂起或 8 字节原子热补丁，必须在目标工作线程启动前安装（如 `LD_PRELOAD` 阶段）。
- 不处理指令跨页/跨函数极端边界，遇此类情况安全返回 `false`。
- `VTableHook` 直接写虚表；若虚表位于 RELRO 只读段，`mprotect` 失败时返回 `false`。
- 不修改 `.eh_frame` 异常展开表（适用于不跨 hook 外抛 C++ 异常的场景）。

### 何时用 `shk` vs 成熟第三方库

如果需要线程安全热补丁、任意奇异指令序言或跨平台支持，优先考虑成熟方案（如 `funchook`、`safetyhook`、`subhook`、`polyhook2`；Windows 平台另见本仓库的 [`../satfix-win/winhook.hpp`](../satfix-win/winhook.hpp) 或 `minhook`）。
当目标是符号齐全的 Linux ELF 程序、希望单头文件零依赖且便于审计魔改时，`shk` 是更轻量的选择。

---

## 6. 自测

```bash
cd hooklib
g++ -O2 -std=c++17 -no-pie -o test_shk test_shk.cpp -ldl
./test_shk

cd test
g++ -O2 -std=c++17 -no-pie -rdynamic -o fake_game fake_game.cpp
g++ -O2 -std=c++17 -shared -fPIC -o test_preload.so test_preload.cpp -ldl
LD_PRELOAD=./test_preload.so ./fake_game
```

预期结果：基础功能测试 4 项全过；端到端拦截 5 次调用；若环境中存在真实 `stellaris` 二进制，全量序言解码失败数为 `0`。
