# AGENTS.md —— 给在这个仓库里干活的 AI / 人

本文件是**工作方式的硬约束**，不是介绍。开工前先读完。

---

## 0. 这个仓库是什么

`satfix` —— 给 Stellaris 的定点算术（`CFixedPoint`）加饱和处理的溢出守卫。

同一份逻辑有两个平台实现，**改一个必须考虑另一个**：

| 目录 | 平台 | 形态 | 当前适配 |
| --- | --- | --- | --- |
| `satfix-win/` | Windows | Stellaris Launcher 插件 DLL（`satfix.dll`），靠硬编码 RVA + 序言签名定位 | **Cygnus v4.6.0**（build `0x6AF6BDEC`，插件 `v0.5.0`） |
| `satfix/` | Linux | `LD_PRELOAD` 共享库（`sat_guard.so`），靠 `dlsym` + 符号名定位 | Cygnus v4.5.2（尚未同步 4.6.0 与部分新目标） |
| `hooklib/` | Linux 共用 | Linux 侧的 hook 引擎（`shk.hpp`）；Windows 侧是自带的 `winhook.hpp` | — |

历史构建时间戳参考：
- **v4.6.0**：`0x6AF6BDEC`（当前主力，`satfix-win/src/satfix_targets_win.generated.hpp` 指向此构建）
- **v4.5.3**：`0x6AE49C1B`
- **v4.5.2**：`0x6ABEAA3F`

游戏更新后的重定位流程见 [`satfix-win/tools/relocate/README.md`](satfix-win/tools/relocate/README.md)。

---

## 1. ★ 最重要的一条：必须结合 Linux 与 Windows 两套反编译源码库

**这是本项目所有定位工作的基础，不要绕过它。**

### 为什么

Windows 的 `stellaris.exe` 被 strip 过：

| 项 | 值 |
| --- | --- |
| 导出符号 | ~110 个（几乎全是 PhysicsFS/CRT，**拿不到任何游戏函数**） |
| C++ 符号 | **无** |
| PDB | **无** |
| `.pdata` | 13 万~14 万+ 个函数（4.6.0 实测 142,256 个），**只有地址区间，没有名字** |
| RTTI | 1269 条类名（只能给类，给不了非虚成员地址） |

而 **Linux 版二进制保留了完整符号表**（近 14 万个函数块，99.999% 有名）。

同版本的两份二进制来自同一次发布构建，所以**同一个函数在两边的逻辑形状、独占常量、ModifierType 序列与调用结构是一致的**，必须跨平台对照定位。

### 源码库在哪（**不在本仓库内**，体量太大）

相对于本仓库上级目录（`../`）：

| 文件 | 说明 |
| --- | --- |
| `../stellaris_4.6_source.cpp` | **Linux 4.6 反编译，有完整符号名** —— 4.6 适配期主力参考（配合 `tools/relocate/locate46.py` 建索引） |
| `../stellaris_4.5.2_source.cpp` | Linux 4.5.2 反编译（339 MB，历史对照基准） |
| `../_analysis/stellaris_4.5.2_win_source.cpp` | Windows 4.5.2 反编译（173 MB，只有 `FUN_xxxxxxxx`） |
| `../_analysis/stellaris_4.5.2_win_symbolized.cpp` | 上一份的「回填符号名」版（见 §9 警告：不要轻信映射名） |
| `../stellaris_4.5_source.cpp` / `../_analysis/stellaris_4.5_win_source.cpp` | 4.5.0 版本，做版本漂移对照用 |
| `../_analysis/win_linux_mapping_final_452.json` | 10186 对 `FUN_ → Linux 名` 字符串指纹映射（仅供参考，不可当身份证明） |
| `../_analysis/_ndefines_thunks.json` | 2369 条 `(NDefines 名, 组, 全局地址)`（4.5.2） |

dump 格式（两份一致，`// ==== <name> End ====` 分隔）：

```cpp
<body 在前>
// ============ FUN_140a14c60 End ===============
<空行 ×3>
```

**解析要点**：函数体在**分隔行之前**。写解析脚本时容易 off-by-one（把名字配到下一个函数体上），第一次读某函数时**先打印它的签名行确认**（`longlong * FUN_xxx(...)`）。

### 标准定位流程（照这个做）

1. **在对应版本的 Linux dump 里按符号名找到目标函数**，读它的完整函数体。
   - ⚠️ **注意版本位移**：大版本升级（如 4.5.3 → 4.6.0）会整体平移 `ModifierType` 枚举值、改变元数据表寻址方式或改写容器结构。**不要拿旧版本的 ModifierType 编号直接搜新版 exe**，必须先从**新版 Linux dump** 重读。
2. **提取跨平台指纹**，按可靠性排序：
   - **独占字符串**（极强）：报错/诊断字符串在 exe 中往往唯一命中。
   - **ModifierType 立即数序列 / 对**（极强）：例如 `mov r9d, <type_add>` 与 `mov r9d, <type_mul>` 同时出现在同一函数中，或 7 个 ModifierType 同序传给 `GetModifierValue`。
   - **独占常量**（很强）：仅在极少数函数中出现的魔数或行号常量。
   - **调用者 / 被调用者序列**（很强）：从已确证函数顺藤摸瓜。
   - **`.pdata` 分块形状**：如 `diplo_weight` 跨版本保持 `43/74/524/5/20` 分块。
   - **结构偏移**（最弱，仅作辅助）：MSVC 与 GCC 布局经常不同，**绝对不能照抄**。
3. **在 Windows exe / dump 里按指纹筛候选**，反汇编或反编译确认函数体与 `.pdata` 起点。
   - 游戏小版本更新优先走 `tools/relocate/` 的**掩码字节比对**（旧版机器码通配 rel32/disp32 后扫新 `.text`）；大版本形变目标改用 `tools/relocate/locate46.py` 走上述指纹法。
4. **【必做】核对 ABI —— 看调用点，不是看函数体**（见 §2）。
5. 把结论更新到 `satfix-win/tools/gen_targets_win.py`：
   - 历史 4.5.3 表为 `CONFIRMED` / `HELPERS`，4.6.0 采用 `RVA_46` / `EVIDENCE_46` 覆盖表；序言签名由脚本从目标 exe 现读，禁止手写；
   - 运行 `python satfix-win\tools\gen_targets_win.py` 重新生成 `src/satfix_targets_win.generated.hpp`。

### 定位手段（按实战效果排序）

1. **掩码字节比对**（版本更新首选）—— 取旧构建机器码，把 `call/jmp` 的 `rel32` 和 RIP 相对寻址 `disp32` 标记为通配，扫新 `.text` + `.pdata` 复核。小版本命中率 >90%，大版本也能先捞回约一半不变函数。
2. **立即数落寄存器检索 / ModifierType 序列** —— `locate46.py scan-imm-fn` 找 `mov r9d, imm` 组合，三个上限与伤害函数全库唯一命中。
3. **调用者法** —— 用 Linux 侧「谁调用 X」的名单找 Windows 侧调用点（如 `CalcStarbaseCapacity` 定位 `ApplyModifierMult`）。
4. **NDefines 名字法** —— 从 `.rdata` 的 `NDefines::<组>::<名>` 字符串反查 `.text` 里的 5 指令注册 thunk，从 `r9` 读出全局地址，再查读该全局的函数（`diplo_weight`、`mpe15`/`mpe7` 靠它破局）。
5. **片区扫** —— 同命名空间函数往往相邻排布（如 `NShipUtil` 片区）。

### 已证伪的思路（别重走）

- **调用图传播**：精度只有 12–26%，枢纽函数吸票，不可用。
- **字段偏移结构指纹**：单独用精度 ~18%，且跨编译器极易漂移。
- **按常量形状找 `apply_mul_cfx`**：Windows 里有 75 个函数含同一套 CModifier 惯用法，常量分不开，必须看调用点。
- **拿旧版 `0xb50679d3` 全库搜 `damage_per_day`**：4.5.2 时命中了单件武器层而非总计层，4.6.0 该常量已变为 `0xb504f333`。

---

## 2. ★ 第二条：函数体一样 ≠ ABI 一样

**每次都要看调用点确认参数个数、参数顺序和返回方式。** 历史已踩过六次大坑（详录见 [`satfix-win/docs/ENGINEERING_NOTES.md`](satfix-win/docs/ENGINEERING_NOTES.md)）：

| 踩坑 | 症状 | 原因 |
| --- | --- | --- |
| `FUN_14075a370` 当成 `cfx_to_fp15` | 活体探针四输入全返回常数 `1767657313` | 函数体公式相同，但 `rdx` 实际是缩放标量，不是返回槽 |
| `cfx_to_fp15` 参数反序 | 探针全返回 0 | 实际为 `(src=rcx, ret=rdx)`，非 `(ret, src)` |
| `SafeSqrt` 与 `Sqrt` 反序 | 探针恒返回哨兵值 `0x5A5A...` | 同类兄弟函数参数顺序相反：`Sqrt(out, src)` vs `SafeSqrt(src, out)` |
| `mpe15` / `mpe7` 跨平台反序 | — | Linux 为 `(out, exp, base)`，Windows 为 `(out, base, exp)` |
| `GetRounded(fp15)` 少传一参 | 探针返回垃圾值 | sret 两参 `(out=rcx, src=rdx)`，误写成单参导致 `rdx` 被日志调用破坏 |
| `detour_max_hp` 读错返回槽 | 误以为三上限返回 0 | 读错了 sret 槽位 |

**教训**：写 detour 前，必须把调用点的汇编或反编译 `FUN_xxx(args...)` 读出来，逐个寄存器和栈参核对。

### 第三层契约：**破坏集（clobber set）**

`stellaris.exe` 使用 MSVC `/GL`（LTCG，全程序优化）编译。LTCG 会按被调函数**实际修改的寄存器**做调用方寄存器分配，而非标准 x64 ABI 的 caller-saved 上限。实机抓到的现行证据（4.5.3 RVA `0xFC5BCC`）：

```asm
call 0x141B50CE0      ; GetRounded（已钩）
mov  edx, eax
mov  rcx, r10         ; 调用后继续用 r10
call r11              ; 调用后继续用 r11
```

`GetRounded` 只碰 `rax/rcx/rdx`，所以调用方将活跃值留在 `r10/r11` 跨调用使用。**只要我们的 C detour 比原函数多破坏一个易失寄存器，就会在某个调用点炸成 `c0000005`（跳到栈上执行 / DEP 违规）。**

**硬性规约**：
- 所有 Windows 侧钩子**必须通过汇编转发桩**（`satfix-win/src/detour_stubs.asm`）安装；
- 桩进入时保存全部易失寄存器（`rcx/rdx/r8-r11` + `xmm0-5`）、转发第 5/6 栈参、调用 C 函数体、返回前原样恢复，使钩子对调用方的破坏集为**空集**；
- **新增或删除钩子时，必须同步维护 `detour_stubs.asm` 并在 `install_hooks()` 中安装对应的 `satfix_stub_*`**。

---

## 3. 本地化新目标或版本重定位的验收标准

缺一不可：

1. **RVA 有可复核依据**（掩码比对 / 调用点 / ModifierType 立即数 / 独占串，写进 `gen_targets_win.py` 的证据字段）；
2. **序言签名已自动生成**（`gen_targets_win.py` 从目标 exe 读取 16 字节，不手写）；
3. **ABI 有调用点证据**（非靠函数体猜测），且结构偏移与数据表常量**已在当前游戏版本的 Windows 侧独立确证**（不照抄 Linux，不沿用旧版假设）；
4. **实机验证**：`stl launch` 后 `logs\satfix.log` 出现 `hooked <key> @ <addr>`，且目标函数确实被游戏调用（`首次调用: <name>`）；
5. **判据有实机证据**：要么抓到真实 EVENT，要么用活体探针 / 专项测试 mod 证明检出与回写链畅通；
6. **未复核的结构偏移或已重构子系统必须显式降级/加安全闸**（如 4.6.0 的 `kVarShadowSupported = false`、`kShipSizeWriteEnabled = false`），绝不盲写内存。

**「装上钩子」不等于「功能可用」** —— 必须看到调用计数增长且零误伤、零崩溃。

---

## 4. 构建 / 测试

### Windows（`satfix-win/`）

```powershell
cd satfix-win

.\build.ps1                # 影子模式（只记录，不改数值）—— 开发/测试用
.\build.ps1 -Replace       # ★ 回写模式（检出溢出就改回饱和值）—— 发布用
.\build.ps1 -TestOnly      # 只跑 winhook 单元测试，不编 DLL
```

`build.ps1` 自动执行 `ml64` 汇编桩、`cl` 编译与 4 步自动化检查（`test_winhook`、`test_stl_fix_win` 含 14 组判定向量、`test_load_plugin`、`check_plugin_pkg.py`），**必须全过**。

产物：
- `build/satfix.dll`（编译中间输出）
- `plugin/`（`stl plugin install --link` 使用的开发目录，运行时产生 `config\`、`logs\`）
- `dist/satfix/`（干净的发布包内容，供合规检查和打包脚本消费）

**两种模式是编译期开关**（`-Replace`），不是配置项 —— 防止手动注入时误改存档。DLL 内置 `satfix-build-mode:write-back` / `:shadow` 标记，日志首行也会打印。

### 实机验证

```powershell
$stl = "$env:LOCALAPPDATA\Programs\Stellaris Launcher\stl.exe"
& $stl plugin install "<repo>\satfix-win\plugin" --link
& $stl launch
# 日志：<repo>\satfix-win\plugin\logs\satfix.log
```

- **改了 DLL 要先关游戏**，否则 `build.ps1` 复制 `satfix.dll` 会因文件被占用而失败。
- 配置**热重载**（每 2 秒检查 `config\satfix.ini` 的 mtime），改设置不必重启游戏。
- `game_click.ps1` / `perf_probe.ps1` / `tick_probe.ps1` / `run_inject_test.ps1` 为实机测试辅助脚本。

### Linux（`satfix/`）

```bash
cd satfix
./build.sh              # 影子模式（含 gen_targets.py --check 与 ABI 回归）
./build.sh replace      # 回写模式
./test_stl_fix          # 离线对拍，必须先全过
```

**注意**：当前 Windows 本机无 Linux 工具链，`satfix/` 目前只能静态审查，不能本地构建验证。

---

## 5. 设计约定

### 策略三分类（`Strategy` 枚举）

| 策略 | 含义 |
| --- | --- |
| `kExact` | 有精确饱和参考实现或硬判据，可逐位比对、可回写 |
| `kInputGuard` | 危险在输入域：先把输入夹到安全域再调原函数 |
| `kObserve` | 只判定「是否进入危险域」，只记日志 |
| `kDisabled` | 地址已确证但 ABI 未确认：安全拒绝安装 |

当前 Windows 分布：**EXACT 9 / INPUT_GUARD 1 / OBSERVE 9**（合计 19；另注意 4.6.0 下 `ship_size_max_hp` 虽标 `kExact` 但受 `kShipSizeWriteEnabled = false` 保护暂不回写）。
**策略统计一律以 `satfix-win/src/satfix_targets_win.generated.hpp` 为准**，核对命令：

```powershell
Select-String -Path satfix-win\src\satfix_targets_win.generated.hpp -Pattern ', k(Exact|Observe|InputGuard|Disabled),' |
    Group-Object { $_.Line -replace '.*,\s*(k\w+),.*','$1' } | Select-Object Name,Count
```

### 回写闸门（重要）

**宁可漏报，不可误改。** 只在游戏值本身呈明确 wrap 特征时才回写：
- 负值（上限 / 伤害 / 船体基础值不可能为负）；
- 或 `0` 而重算为正 / 加算项塌 0 且倍率 ≥ 1e7（护盾 / 装甲塌 0 现场）。

正常正值哪怕重算不等，也绝不改写。漏掉条件性加法修正只会让重算偏小，方向上是安全的。

### 性能纪律

热路径函数每局被调用**数百万至数千万次**（`Atan2` 5000 万+、`ApplyModifierMult` 3000 万+、`CalcMax*` 各数百万次）。必须遵守：

- **能早退就早退**：如 `detour_max_hp` 所有回写分支都要求 `v <= 0`，正常 `v > 0` 直接返回；
- **热路径用 `whk::fast_read`，不用 `safe_read`**：`safe_read` 每次调 `VirtualQuery`（内核切换）。仅当指针来自游戏自身传入的可信对象时用 `fast_read`（SEH 兜底）；解析出的 RVA、动态全局指针、vtable 探测或猜测偏移**必须继续使用 `safe_read`**；
- **诊断开关默认关闭**：任何逐调用开销（直方图计数、诊断日志、绕过早退路径）都必须默认关闭并可配置开关。

### 日志

Windows 日志上限 `SATFIX_MAX_LOGS = 20000` 行，使用 `SRWLOCK` + 单次整行缓冲 `fputs` 防多线程断行；事件类日志必须限流（如按 `design` 指针去重），避免详情面板每帧重算刷满日志。

---

## 6. 文档与权威来源

| 文件 | 作用 |
| --- | --- |
| `satfix-win/tools/gen_targets_win.py` | **Windows 目标、RVA（含 `RVA_46` 覆盖表）与证据的唯一权威来源** |
| `satfix-win/src/satfix_targets_win.generated.hpp` | 由 `gen_targets_win.py` 生成的头文件 —— **禁止手改** |
| `satfix-win/plugin/stl-plugin.json` | **版本号 `version` 与适配时间戳清单的唯一来源**（`build.ps1` 和 `package_release.ps1` 均从此读版本） |
| `satfix-win/RELEASE_NOTES.md` | **GitHub Release 发布说明的唯一来源**，被 `package_release.ps1` 按 `## v<version>` 正则解析 —— **严禁破坏标题格式** |
| `README.md` | 仓库总览（玩家 + 开发者入口） |
| `satfix-win/README.md` | Windows 插件当前架构、目标、配置与运行手册 |
| `satfix-win/docs/ENGINEERING_NOTES.md` | Windows 逆向方法论、ABI/LTCG 踩坑录与版本演进档案 |
| `satfix-win/tools/relocate/README.md` | 游戏更新后重定位工具链操作手册 |
| `satfix/README.md` | Linux 侧文档 |

---

## 7. 必须遵守插件手册

Windows 侧是 **Stellaris Launcher 插件**，改代码前必须核对手册 §6（编写 DLL 的规则）与 §13（发布前检查清单）：
> `../stellaris-launcher/docs/PLUGIN_HANDBOOK.zh-CN.md`

### 硬性要求（§6，违反会导致崩溃/卡死/被拒）

| 条款 | 要求 | 本插件现状 |
| --- | --- | --- |
| 6.1 | `DllMain` 只创建线程；不等待、不 `LoadLibrary`、不碰引擎、不做文件/网络 | ✅ 只 `DisableThreadLibraryCalls` + `CreateThread` + `CloseHandle` |
| 6.2 | 从**自己模块地址**取插件路径；不用 CWD、不写死 `Documents\…` | ✅ `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` |
| 6.3 | 引擎函数只在游戏主线程调用；自有线程只做等待与文件 mtime 检查 | ✅ detour 做轻量工作，重活推迟到主线程泵 |
| 6.4 | 原始内存读用 SEH 包住；**严禁照抄 Linux 结构偏移** | ✅ `whk::safe_read` / `fast_read`；偏移必在 Windows 侧独立实证 |
| 6.5 | detour 必须调原函数；不假设自己是唯一钩子；不恢复他人钩子 | ✅ `TypedHook::call()` |
| 6.6 | **不卸载自己**（不 `FreeLibraryAndExitThread`） | ✅ 源码中无调用 |
| 6.7 | 静态运行库 `/MT`；不弹控制台；只支持 x64 | ✅ `/MT`、无 `AllocConsole`、仅依赖 `KERNEL32.dll` |

**6.4 血泪教训**：`CShipSize::max_hitpoints` 在 Linux 为 `ship_size + 0x678`，在 Windows 为 `self + 0x6b8`（子对象基址 `+0x40` 错位）。即使 `ReadMember` 里三个 token 到偏移的映射看起来与 Linux 逐字相同，**因为 `this` 指针基址不同，照抄 `0x678` 会去改一个 bool**。证明一个偏移必须使用**独立于 Linux** 的判据（如 HULLMAP 探针：拿已确证的同义值在同对象内存内反扫匹配槽位），并且大版本更新后必须复核（复核前用安全闸暂停写回）。

**6.3 线程安全教训**：引擎工作线程（如 `CPdxTaskScheduler`）可能并发进入被 hook 函数，绝不可在 detour 里调用非线程安全的本地化/UI API（早年调 `CShipSize::GetName()` 导致 SEGV）。

### 清单与校验（§4 / §7 / §10 / §13）

- `plugin/stl-plugin.json` 必须包含 `"schema": 2`、保持 `id: "satfix"` 不变、`game.exe_timestamps`（嵌在 `game` 下）、有效的 `config[].default`、以及自动更新字段 `update.github` / `update.asset`。
- DLL 自身必须再做一次 PE 时间戳 + 16 字节序言签名校验。
- 发布包 zip 内容即插件目录，**严禁包含** `config\`、`logs\` 或构建中间文件。
- 自检命令：`python satfix-win\tools\check_plugin_pkg.py satfix-win\dist\satfix [--exe <path>]`。

---

## 8. 发布流程

```powershell
cd satfix-win
.\build.ps1 -Replace                    # 必须是回写模式
.\tools\package_release.ps1             # 校验 + 打包（版本号取自 plugin\stl-plugin.json）
```

`package_release.ps1` 参数：`-OutDir`（默认 `release/`）、`-Mode`（`write-back` / `shadow` / `any`，**默认 `write-back`**）、`-Exe`。版本号自动从 `plugin/stl-plugin.json` 读取，不通过参数传。

打包脚本会校验：构建模式、无 `config\`/`logs\`、默认配置存在、`RELEASE_NOTES.md` 含 `## v<version>` 段落，并生成 `.zip`、`.sha256` 与 `.zip.notes.md`。随后手工打 tag 并创建正式 Release（非草稿/预发布）：

```powershell
git tag v<version> && git push origin v<version>
gh release create v<version> satfix-v<version>.zip satfix-v<version>.zip.sha256 `
    --title "satfix v<version>" --notes-file satfix-v<version>.zip.notes.md
```

发布仓库：`github.com/Aa728848/satfix`，asset 匹配 `satfix-*.zip`。

---

## 9. 反模式（出现即为错误）

1. **不看对应版本的 Linux 源码就硬猜 Windows 函数** —— 最昂贵的错误来源。
2. **拿旧版本（如 4.5.3）的 ModifierType 枚举号或结构偏移直接套在新版（如 4.6.0）上**。
3. **靠映射表的名字当身份证明**（`win_linux_mapping_final_452.json` 的 `exact` 仅指字符串指纹唯一命中）。
4. **靠函数体猜 ABI** —— 必须看调用点核对参数个数、顺序与 sret。
5. **在 Windows 侧直接把 C detour 当钩子装上去而不走 `detour_stubs.asm`** —— 会踩中 LTCG 破坏集导致偶发 CTD。
6. **「钩子装上了」就宣布完成** —— 必须看到调用计数增长、判据或探针通过。
7. **改回写路径不设保守闸门 / 未复核偏移就开放写回**。
8. **在热路径加重活**（`VirtualQuery`、逐调用日志或格式化）。
9. **手改 `src/satfix_targets_win.generated.hpp`** —— 必须改 `tools/gen_targets_win.py` 后重新生成。

---

## 10. 快速命令备忘

```powershell
# 1) 查看当前 Windows 目标清单与策略分布
Select-String -Path satfix-win\src\satfix_targets_win.generated.hpp -Pattern '^    \{"'

# 2) 游戏更新后先校验 RVA/时间戳/签名是否漂移
python satfix-win\tools\gen_targets_win.py --check

# 3) 重新生成目标头文件
python satfix-win\tools\gen_targets_win.py

# 4) 构建 + 全套离线测试 + 组装发布目录与合规校验
cd satfix-win; .\build.ps1 -Replace

# 5) 独立检查发布包是否合规
python satfix-win\tools\check_plugin_pkg.py satfix-win\dist\satfix
```
