# shk —— 给 Linux 游戏做 hook 的最小通用 C++ 库

针对「符号齐全的本地 ELF 可执行文件」（Stellaris 的 `stellaris` 就是：
`ELF64 EXEC` 非 PIE、未 strip、带 18.7 万个动态符号）写的一个**零依赖单头文件** hook 库。

```
hooklib/
  shk.hpp                 库本体（单头文件，C++17，无第三方依赖）
  example_stellaris.cpp   在 Stellaris 里 hook Shoot / UpdateFleetSize 的示例
  test_shk.cpp            功能自测 + 对真实 stellaris 做 13.9 万函数解码压力测试
  test/fake_game.cpp      假“游戏”进程（导出同名符号）
  test/test_preload.cpp   端到端验证：LD_PRELOAD 进假游戏并拦截调用
  debug_hook.cpp          排查用的小程序（打印蹦床字节）
```

---

## 1. 快速上手

```bash
# 编译你自己的 hook 动态库
g++ -O2 -std=c++17 -shared -fPIC -o my_hook.so my_hook.cpp -ldl

# 启动游戏（在游戏目录）
LD_PRELOAD=$PWD/my_hook.so ./stellaris
```

写一个 hook 只要三步：

```cpp
#include "shk.hpp"

// ① 用不带类定义的函数指针描述目标签名，this/参数一律 void*
using ShootFn = bool (*)(const void* self, const void* micro, void* target);
shk::TypedHook<ShootFn> g_shoot;

// ② 写 detour；要调用原函数就用 g_shoot.call(...)
bool my_shoot(const void* self, const void* micro, void* target) {
  return g_shoot.call(self, micro, target);   // 想拦截就 return false
}

// ③ 用「全局对象的构造函数」安装（见下面第 3 节，别用 __attribute__((constructor))）
struct Installer { Installer() { g_shoot.install("_ZNK16CWeaponComponent5Shoot...", &my_shoot); } };
Installer g_installer;
```

按名字找不到符号时，也可以直接给地址（Stellaris 非 PIE，`nm` 出来的地址就是运行时地址）：

```cpp
g_shoot.install((void*)0x1f916b0, &my_shoot);   // CWeaponComponent::Shoot
```

---

## 2. API

| 接口 | 作用 |
| --- | --- |
| `shk::resolve(name)` | 按 mangled 名解析地址：先 `dlsym(RTLD_DEFAULT)`，失败再自己解析 `/proc/self/exe` 的 `.symtab`/`.dynsym`（PIE 会自动加基址） |
| `shk::resolve_as<Fn>(name)` | 同上，带类型转换 |
| `shk::write_code(dst, src, len)` | 写代码段（自动 `mprotect` 成 RWX 再改回 R-X） |
| `shk::InlineHook` | `install(target/detour)`、`install(symbol/detour)`、`uninstall()`、`trampoline()`、`target()` |
| `shk::TypedHook<Fn>` | 类型安全包装，`call(args...)` 调用原函数 |
| `shk::VTableHook` | 换虚表槽：`install(vtable, index, detour)`，不碰 `.text`，最安全 |
| `shk::alloc_near(hint, size)` | 在 hint 的 ±2GB 内分配内存（蹦床必须离目标足够近） |

---

## 3. 两个必须知道的坑（都是实测踩出来的）

### 3.1 不要用 `__attribute__((constructor))` 安装 hook

```
输出顺序（实测）：
  constructor attribute       ← __attribute__((constructor))
  A ctor (static init)        ← _GLOBAL__sub_I_...（全局对象构造）
  B ctor (static init)
```

GCC 把 `__attribute__((constructor))` 排在同一个编译单元的静态初始化**之前**。
于是流程变成：

1. constructor 里 `g_shoot.install(...)` → 补丁打进 `.text`，全局对象里记下 trampoline；
2. 紧接着 `_GLOBAL__sub_I_...` 运行，把 `g_shoot` **重新零初始化**；
3. 游戏调用被 hook 的函数 → detour 里 `g_shoot.call()` 发现 trampoline 是 `nullptr` → 崩溃。

**正确做法**：把所有 hook 对象定义在前，然后用一个全局对象的构造函数安装（同一编译单元内按定义顺序初始化）。

### 3.2 入口补丁不要破坏寄存器

常见写法 `48 B8 <imm64> FF E0`（`mov rax, imm64; jmp rax`）会写坏 `rax`。
虽然 `rax` 是 caller-saved，理论上安全，但只要「调用方」和「被 hook 的函数」在同一个编译单元
（或开了 LTO），编译器就知道目标的 clobber 集合，可能把活跃变量放进 `rax`，于是调用点逻辑被破坏
（实测表现：`for` 循环计数不前进 → 死循环 / 崩溃）。

本库的做法：在目标附近分配一页内存，里面放

```
[蹦床] 原始前 N 条指令副本 + FF 25 00000000 <回到原函数+N>     ; jmp qword ptr [rip+0]
[relay] FF 25 00000000 <detour 绝对地址>                       ; 同上
```

入口只写 **5 字节** `E9 rel32 -> relay`，**一个寄存器都不碰**，而且几乎不会越界写到下一个函数。

（同理，测试用的「假游戏」要给目标函数加 `noipa`，否则 `main` 也会基于 clobber 知识做优化。）

---

## 4. 设计细节

* **指令长度解码器**：只覆盖函数序言常见指令；遇到不认识的就**拒绝安装**而不是瞎猜。
  实测对真实 `stellaris` 的 139,452 个 `STT_FUNC` 符号做「前 12 字节必须能完整解码」的扫描，
  **失败 0 个**（`test_shk` 的输出）。想 100% 覆盖所有 x86-64 指令，把 `shk::detail::decode`
  换成 Zydis / hde64 即可，接口只有 `insn_t{len, rip_off, rel_off, rel_size}`。
* **重定位**：复制进蹦床的指令会修正 `rel8/rel32` 相对跳转和 RIP 相对寻址；越界就放弃安装（不会写坏内存）。
* **蹦床就近分配**：用 `MAP_FIXED_NOREPLACE` 在目标 ±1.75GB 内找空页，保证上面两种重定位都放得下。
  同时入口 `E9 rel32` 也只够得到 ±2GB，所以 relay 也放在这一页。
* **符号尺寸保护**：解析 `/proc/self/exe` 的 `.symtab`，如果目标符号剩余字节数 < 5，拒绝安装
  （防止把小函数和它的邻居一起写坏）。
* **重复安装保护**：用一张原子表记录本库 hook 过的地址。不用「入口是不是 E9」判断，
  因为合法的链接器 thunk 本身就是 `E9` 开头。

---

## 5. 已知限制

* 只支持 **Linux x86-64**（代码里有 `#error` 保护）。
* **安装/卸载不是线程安全的**：请在游戏线程跑起来之前装，或者在确定目标函数没人在跑的时候装。
  5 字节补丁不是原子写；本库没有做「线程挂起」或「8 字节原子热补丁」。
* 蹦床按「拷贝完整指令」实现，不处理「指令跨页/跨函数」等极端情况（会直接拒绝安装）。
* `VTableHook` 直接改虚表内存；如果虚表落在 RELRO 只读段，`mprotect` 会失败并返回 false。
* 没有处理 C++ 异常表（`.eh_frame`）——被 hook 的函数如果会抛异常并且需要跨 detour 展开，
  需要额外处理，本项目场景（游戏内 C++ 函数一般不外抛）不需要。

---

## 6. 该用现成库还是这个？

你机器上的 xmake 仓库缓存里已经有一堆成熟方案（`~/.xmake/repositories/build-artifacts/packages/`）：

| 库 | 说明 |
| --- | --- |
| `funchook` | 小巧、纯 C、Linux 支持好，自带指令解码（Zydis 可选），API 简单 |
| `safetyhook` | 现代 C++（header-only），依赖 Zydis，功能全，适合复杂场景 |
| `subhook` | 极简，5 字节相对跳转，接口小 |
| `shadowhook` | 移动端为主，x86-64 也支持 |
| `polyhook2` | 功能最全（含 VEH/硬件断点等），依赖较重 |
| `minhook` | **仅 Windows**，Linux 用不了 |

**什么时候用它们**：需要 hook 各种奇怪指令序言、需要线程安全安装、需要 hot-patch 正在执行的函数。

**什么时候用 shk**：
* 目标就是像 Stellaris 这种「非 PIE + 符号齐全」的本地 ELF；
* 想要一个能直接读、能改、能塞进自己项目、没有第三方依赖的单文件；
* 主要需求是「按符号名拦截某个 C++ 成员函数，并调用原函数」。

---

## 7. 自测

```bash
cd hooklib
g++ -O2 -std=c++17 -no-pie -o test_shk test_shk.cpp -ldl
./test_shk            # 功能测试 + 对真实 stellaris 的解码扫描

cd test
g++ -O2 -std=c++17 -no-pie -rdynamic -o fake_game fake_game.cpp
g++ -O2 -std=c++17 -shared -fPIC -o test_preload.so test_preload.cpp -ldl
LD_PRELOAD=./test_preload.so ./fake_game
```

预期：功能 4 项全过；真实二进制 139,452 个函数解码失败 0 个；端到端拦截 5 次调用。
