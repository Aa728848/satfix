# satfix-win —— Stellaris 定点溢出守卫（Windows DLL 插件）

`satfix` 的 Windows x64 实现，遵循 [Stellaris Launcher 插件手册 v2](https://github.com/Yidhar/stellaris-launcher/blob/main/docs/PLUGIN_HANDBOOK.zh-CN.md) 构建。

- **当前插件版本**：`v0.5.0`（`satfix — Fixed-Point Overflow Guard`）
- **当前适配游戏**：**Stellaris Cygnus v4.6.0**（`stellaris.exe` PE 时间戳 `0x6AF6BDEC`）
- **Hook 覆盖**：**19 个已确证目标**（EXACT 9 / INPUT_GUARD 1 / OBSERVE 9）+ **6 个辅助函数**；全部通过汇编转发桩安装，确保零寄存器破坏。

> 历史逆向定位证据、6 次 ABI / 偏移踩坑复盘、LTCG 寄存器保全事故分析以及 4.5.2 → 4.5.3 → 4.6.0 演进详情已独立归档至 [`docs/ENGINEERING_NOTES.md`](docs/ENGINEERING_NOTES.md)，本文档聚焦当前版本的架构、行为与操作说明。

---

## 1. 目录与核心模块

| 文件 / 目录 | 作用 |
| --- | --- |
| `src/sat_guard_win.cpp` | 插件本体：`DllMain`、日志系统、配置热重载、主线程泵、19 个 detour、活体探针 |
| `src/detour_stubs.asm` | 19 个钩子的 MASM64 寄存器保全转发桩（应对 MSVC `/GL` LTCG 破坏集契约） |
| `src/satfix_targets_win.generated.hpp` | **自动生成，勿手改**；包含当前构建的 PE 时间戳、19+6 组 RVA 与 16 字节序言签名 |
| `winhook.hpp` | Windows x64 hook 引擎（5 字节 `E9 rel32` → relay → 蹦床，含 rel8→rel32 加宽与线程挂起原子补丁） |
| `satfix128.hpp` | 128 位中间量算术（基于 `<intrin.h>` 的 `_umul128`/`_mul128`/`_udiv128` + 自写长除，替代 GCC `__int128`） |
| `stl_fix_win.hpp` | 定点饱和参考实现（`CFixedPoint` 十进制与 `fpml` 二进制方言，无外部依赖） |
| `satfix_decision.hpp` | 独立于 hook 机制的纯判定函数 + 14 组进程内自检向量表 |
| `plugin/` | 开发联调目录：`stl-plugin.json`、`defaults/satfix.ini`（以及构建复制过来的 `satfix.dll`） |
| `test/` | 3 套原生离线自测：`test_winhook.cpp`、`test_stl_fix_win.cpp`、`test_load_plugin.cpp` |
| `tools/` | `gen_targets_win.py`、`check_plugin_pkg.py`、`package_release.ps1`、dump 索引与指纹工具 |
| `tools/relocate/` | 游戏更新后的跨版本重定位工具链（见 [`tools/relocate/README.md`](tools/relocate/README.md)） |
| `build.ps1` | 一键脚本：汇编 + 编译 + 3 套原生自测 + 组装 `dist\satfix\` + 合规检查 |
| `RELEASE_NOTES.md` | 发布说明唯一来源（被 `tools/package_release.ps1` 按 `## v<version>` 解析） |

---

## 2. 架构设计

### 2.1 `winhook.hpp` —— Hook 引擎

继承自 Linux 侧 `hooklib/shk.hpp` 的 5 字节入口补丁与指令重定位算法，适配 Windows 平台并修复了原实现的两项缺陷：

- **两跳结构**：在目标函数 ±1.75 GB 范围内用 `VirtualQuery` + `VirtualAlloc` 申请临近页放置 `relay`（`FF 25 00000000 <detour64>`）与蹦床，原函数入口仅改写 5 字节 `E9 rel32 -> relay`，不触碰任何寄存器。
- **rel8 → rel32 加宽**：蹦床拷贝序言时自动将短条件跳（`0x70..0x7F`）加宽为 `0F 8x rel32`，短无条件跳（`0xEB`）加宽为 `E9 rel32`，并重算所有 RIP 相对与分支位移。
- **线程挂起式热补丁**：写 5 字节补丁期间挂起同进程其余线程并调用 `FlushInstructionCache`，避免并发执行踩到半截指令。
- **双档安全内存读取**：
  - `whk::safe_read`：`VirtualQuery` 可读性预检 + 独立 `seh_memcpy`（避免 MSVC C2712），用于 RVA、全局指针、vtable 验证与不确定指针；
  - `whk::fast_read`：仅 SEH 兜底、不进内核态，用于高频热路径上来自游戏的可信对象指针。
- **可恢复注册表**：统一 `HookRegistry` 单例管理已安装地址，失败回滚与卸载重装均能正确清理槽位。

### 2.2 `detour_stubs.asm` —— LTCG 寄存器保全桩

`stellaris.exe` 使用 MSVC `/GL`（LTCG）编译。编译器会跨函数传播被调函数的**实际寄存器破坏集**，使调用方把活跃值放在标准 ABI 定义为 caller-saved 的寄存器（例如 `r10`/`r11`）里跨调用保留。如果普通 C detour 改写了这些寄存器（尤其在首次写日志或心跳时），调用方后续 `call r11` 就会直接跳到栈地址触发 `c0000005`（DEP 执行违规）。

因此全部 19 个钩子一律通过 `detour_stubs.asm` 中的转发桩安装：
1. 入口保存全部易失寄存器（`rcx/rdx/r8-r11`、`xmm0-5`），维持 16 字节栈对齐；
2. 转发第 5、6 个栈参数；
3. 调用对应的 C `detour_*` 函数体，暂存 `rax` 返回值；
4. 原样恢复所有保存的寄存器并返回。

这使得钩子对游戏调用点的寄存器破坏集恒为**空集**，比原函数更保守。

### 2.3 线程模型与主线程泵

严格遵循插件手册 §6.1 与 §6.3：
- **`DllMain`**：只调用 `DisableThreadLibraryCalls` + `CreateThread`，不等待、不加载 DLL、不碰引擎或文件。
- **后台初始化/监听线程**：完成构建校验、安装钩子后，每 2 秒检查一次 `config\satfix.ini` 的修改时间并置位原子标志 `g_reload_requested`，绝不碰游戏对象或引擎函数。
- **主线程泵**：配置重读、统计汇总等重活推迟到游戏线程下一次进入被 hook 函数时执行；多线程日志通过 `SRWLOCK` + 整行单次缓冲 `fputs` 保证不交错断行。

### 2.4 双重版本校验

Windows 版 `stellaris.exe` 无 PDB 且不导出 C++ 游戏符号，因此采用两层防护：
1. **启动器层**：`plugin/stl-plugin.json` 的 `game.exe_timestamps` 声明适配构建；
2. **DLL 运行时层**：启动时校验主模块 PE `TimeDateStamp` 是否等于 `SATFIX_WIN_EXE_TIMESTAMP`，随后逐目标比对 16 字节序言签名；任一项不匹配即安全停用并记日志，绝不盲目打补丁。

---

## 3. 目标清单（Cygnus v4.6.0 / `0x6AF6BDEC`）

策略分布以 `src/satfix_targets_win.generated.hpp` 为权威：**EXACT 9 / INPUT_GUARD 1 / OBSERVE 9**（合计 19），另有 **6 个辅助函数**。

### 3.1 19 个 Hook 目标

| Key | 目标函数 | 4.6.0 RVA | 策略 | 当前行为与说明 |
| --- | --- | :---: | :---: | --- |
| `cfx_get_rounded` | `CFixedPoint::GetRounded() / GetRounded64()` | `0x01CFF460` | EXACT | MSVC COMDAT 折叠共用同一地址；修 `x±50000` 溢出（`INT64_MAX` 原版返负值） |
| `cfx_to_fp15` | `CFixedPoint::operator fpml<...,15>() const` | `0x01CFF360` | EXACT | ABI `(src=rcx, ret=rdx)`；理论上不会溢出，保留作证明与探针 |
| `apply_mul_cfx` | `CModifier::ApplyModifierMult(CFixedPoint&, ...)` | `0x004025F0` | EXACT | 修正乘法主出口；复用返回值（实际倍率）做 128 位饱和复算 |
| `apply_mul_fp15` | `CModifier::ApplyModifierMult(fpml<...,15>&, ...)` | `0x00402730` | EXACT | 同上，乘法在 2^15 编码上执行 |
| `shield_max` | `NShipUtil::CalcMaxShieldHitPoints` | `0x00BB52E0` | EXACT | 忠实重算 + 「加算溢出塌成 0」封顶到 `INT64_MAX` |
| `armor_max` | `NShipUtil::CalcMaxArmorHitPoints` | `0x00BB5CD0` | EXACT | 同上，忠实重算 + 塌 0 / 负值封顶 |
| `hull_max` | `NShipUtil::CalcMaxHitPoints` | `0x00BB4A60` | EXACT | 近似重算（未建模三段条件加法，方向安全）+ 负值封顶 |
| `damage_per_day` | `NShipUtil::CalcAverageDamagePerDay` | `0x00BB7D70` | EXACT | 舰船详情面板「伤害」负值/越界封顶（**仅影响 UI 显示，不影响实战伤害**） |
| `ship_size_max_hp` | `CShipSize::PostReadInit()` | `0x00E42660` | EXACT | `max_hitpoints` 源头负值兜底；**4.6.0 偏移已活体复核为 `+0x6f0`，回写已恢复（仅负值触发，正常正值一律不动）** |
| `cfx_sqrt` | `CFixedPoint::Sqrt() const` | `0x01CFBC90` | INPUT_GUARD | 负输入在原实现会被当作极大无符号数迭代；检测并夹取 |
| `cfx_safe_sqrt` | `CFixedPoint::SafeSqrt() const` | `0x01CFF8F0` | OBSERVE | 记录负输入；ABI `(src=rcx, out=rdx)` |
| `cfx_round_to` | `CFixedPoint::RoundTo(CFixedPoint const&)` | `0x01CFF4A0` | OBSERVE | 记录 `divisor==0` 与 `v + divisor/2` 溢出 |
| `cfx_atan2` | `CFixedPoint::Atan2(...)` | `0x01CFF5C0` | OBSERVE | 记录参数平方越界量级 |
| `cfx_get_rounded_fp15` | `CFixedPoint::GetRounded(fpml<...,15> const&)` | `0x01CFF3C0` | OBSERVE | ABI `(out=rcx, src=rdx)`；4.6.0 起游戏自身已加入饱和钳位 |
| `var_multiply` | `CMultiplyVariableEffect::ExecuteActual` | `0x018E8E40` | EXACT | **4.6 token 链已适配：忠实复算并比对；mismatch 即游戏 64 位算错，回写精确饱和值（`v1!=sat` 已证明完备无假阳）** |
| `var_add` | `CAddVariableEffect::ExecuteActual` | `0x018E83D0` | EXACT | 同上（`cfx::add`），忠实复算 + 回写饱和值 |
| `diplo_weight` | `CPopJob::CalcDiplomaticWeight` | `0x00916BA0` | OBSERVE | 记录负值或极端越界的外交权重 |
| `mpe15` | `NCombatRules::CalcMilitaryPowerExponent<15>` | `0x00BAE130` | OBSERVE | 舰队实力指数（fp15），ABI `(out, base, exp)`；记录中间积风险 |
| `mpe7` | `NCombatRules::CalcMilitaryPowerExponent<7>` | `0x00BAE2A0` | OBSERVE | 舰队实力指数（fp7），同上 |

> **唯一未定位项 `cfx_safe_sqrt_int`（`CFixedPoint::SafeSqrt(long long)`）**：经 4.5.2 反编译核实，Windows 版 `MTTHModifyNumber` 的 `case 0xf` 直接调用引用版 `SafeSqrt(CFixedPoint const&)` 且自带负值判断，MSVC 不生成整数重载及其 `p * 100000` 溢出点，因此**并非功能缺口**。

### 3.2 6 个辅助函数（只解析地址与验签，不装钩子）

| Key | 对应函数 | 4.6.0 RVA | 当前用途 |
| --- | --- | :---: | --- |
| `ship_size_of` | 从 `CBaseDesignImplementation` 取当前成长阶段 `CShipSize*` | `0x003AEA80` | **启用**：三上限重算链第一步（调用前先校验 `design` vtable 落在本映像内） |
| `modifier_value` | `CShipSize::GetModifierValue(CModifier const&, ModifierType)` | `0x00E40D40` | **启用**：三上限重算链取值原语 |
| `access_var_pointer` | `AccessVariablePointer` | `0x00B00910` | 暂未调用（4.6.0 第二参由 `CString*` 改为 `uint16` token） |
| `cvars_get` | `CVariables::GetVariable` | `0x00295C10` | 暂未调用（4.6.0 变量效果链已不再走此函数） |
| `cvars_set` | `CVariables::SetVariable` | `0x0088D260` | 暂未调用（4.6.0 改为 token 键控写回） |
| `cfp_getvalue` | `CFixedPointVariableValue::GetValue` | `0x003E3CF0` | 暂未调用（随变量影子复算一并停用） |

---

## 4. 核心修复机制与 4.6.0 适配变化

### 4.1 护盾 / 装甲 / 船体上限重算与「塌成 0」修复

重算链完全复用游戏自身原语并改用 128 位饱和算术：

```text
size   = ship_size_of(design)
base   = *(design + design_off) + modifier_value(size, mods, type_add) [+ cls_base]
add    = modifier_value(size, mods, type_mul) + ship_class_mod(design, mods, class_table) [+ cls_mul]
factor = add + 100000
sat    = cfx::mul(base, factor)   // 128 位饱和乘法
```

4.6.0 实证常量与表地址（`src/sat_guard_win.cpp`）：

| 目标 | `design` 偏移 | 加算 / 乘算 type | 条件性船级对 | 舰船等级修正表 RVA（15 项） | `add_carries_value` |
| --- | :---: | :---: | :---: | :---: | :---: |
| `hull_max` | `0x10` | `0x20` / `0x21` | — | `0x2A2BCA4` | `false`（值在 `base`） |
| `armor_max` | `0x70` | `0x26` / `0x27` | `0x1d2` / `0x1d3` | `0x2A2BCE0` | `true`（值在加算项） |
| `shield_max` | `0x130` | `0x30` / `0x31` | `0x1d4` / `0x1d5` | `0x2A2BD1C` | `true`（值在加算项） |

此外，4.6.0 的 ModifierType 元数据表改为**运行时指针间接寻址**（指针变量 RVA `0x2A29CF0`，静态映像中为 `0`、启动后由引擎填充），插件在内联扫表时已改为 `safe_read` 动态解引用该指针。

**回写闸门与热路径优化**：
- **早退**：所有回写分支均要求游戏返回值 `v <= 0`；正常舰船 `v > 0` 直接返回，跳过重算与扫表开销。
- **塌成 0 兜底**（仅 `add_carries_value == true` 的护盾/装甲）：当加算项因溢出先 wrap 成负再被 `GetModifierValue` 掩码夹成 `0`，表现为 `add_in == 0` 且乘算倍率 ≥ `1e7` 倍时，判定塌 0 并封顶回写 `INT64_MAX`。
- **保守原则**：正常正值哪怕重算不等也绝不改写；回写前先检查 `design` 的 vtable 指针合法性，避免数据库加载期的栈上临时对象导致虚调用崩溃。

### 4.2 面板「伤害」（`damage_per_day`）与船体基础值（`ship_size_max_hp`）

- **`damage_per_day`**：拦截 `NShipUtil::CalcAverageDamagePerDay` 的 sret 返回槽；伤害总计不可能为负，检出负值或越过上限即封顶为 `INT64_MAX`。经调用图核实，全部 8 个调用者均属 UI/工具提示层，只修正界面显示，不影响战斗伤害结算。
- **`ship_size_max_hp`**：拦截 `CShipSize::PostReadInit()`，在 mod 加载 `ship_sizes/*.txt` 阶段从源头拦截 `max_hitpoints` 的 wrap 负值（否则污染 `design + 0x10` 后下游重算会产生「同向错」）。
  - ✅ **4.6.0 偏移已复核**：4.5.3 的 `+0x6b8` 在 4.6.0 已失效。实机对 320 个 `CShipSize` 对象做「已知脚本船体值反扫」，唯一同时命中全部 11 个基础值（`@transport_hp=100` … `@juggernaut_hp=100000`）的槽位是 `+0x6f0`；`+0x6b8` 上是 0/0.75/1.0/1.5 之类小数（别的字段）。源码已改为 `kShipSizeMaxHpOff=0x6f0` 且 `kShipSizeWriteEnabled=true`，回写恢复，仍受「仅负值触发」硬闸门保护。

### 4.3 4.6.0 变量链已适配 token 键控（检测 + 回写）

4.6.0 将脚本变量存储改为 token 键控哈希表：token 内联在效果对象 `this+0xc0`（Windows；Linux 0xb8），经 `AccessVariablePointer(scope, token)` 取容器，再用 `CPdxUnorderedMap::FindGet(容器, token)`（0x0088D120）读值（指针处即 CFixedPoint）、`0x0088D260` 写回；操作数为 `CFixedPointVariableValue::GetValue(this+0x298, scope)`。`access_var_pointer`、`cvars_findget`、`cvars_set`、`cfp_getvalue` 四个 helper 的 RVA 与 ABI 均已由 4.6 Windows 反汇编确证并接入。

源码 `kVarShadowSupported = true`：`var_multiply` / `var_add` 现在做**忠实影子复算**（读 v0、操作数 d，调原函数后读回 v1，与 `cfx::add/mul` 比对，不一致记 EVENT）。实机样本 `v0=200000 d=100000 game=300000 sat=300000 一致` 证明读链正确、零崩溃。

**已回写**（`kVarWriteEnabled = true`）：判据 `v1 != sat` 被证明**完备且无假阳**——`cfx::mul / cfx::add` 是精确饱和运算（800 万组含 INT64 极值随机对拍，与「128 位真值向零截断再夹到 int64」逐位相等、0 反例）；而游戏的 64 位游戏乘法 `mul_game` 只在**它自己算错**时才 ≠ 精确值（真值越界，或拆分中间量 `(X%1e5)*Y` 在 |操作数|≳9e8 时溢出）。所以 mismatch ⇒ 游戏算错 ⇒ 写回精确饱和值一定是**修复**；合法负值只要不越界就精确相等、不触发。与船体/护盾同一套「忠实重算 + 越界兜底」。

---

## 5. 配置与日志

配置文件位于 `<插件目录>\config\satfix.ini`（默认模板见 [`plugin/defaults/satfix.ini`](plugin/defaults/satfix.ini)）。文件缺失时自动使用内置默认值；修改后每 2 秒自动热重载，无需重启游戏。

| 配置项（`[general]`） | 默认值 | 说明 |
| --- | :---: | --- |
| `enabled` | `true` | 总开关；`false` 表示不安装钩子 / 停用判定 |
| `verbose_events` | `true` | 是否逐条记录 EVENT 日志；关闭后只保留计数与心跳 |
| `heartbeat` | `false` | 是否开启周期汇总日志 |
| `heartbeat_every` | `200000` | 每累计 N 次 hook 调用打印一次分类计数 |
| `max_hp_cap` | `1000000000000000000` | 退化路径下的上限阈值（CFixedPoint 存储值，`1e18` ≈ `1e13` 游戏单位） |
| `verify_max_hp` | `true` | 开启护盾/装甲/船体上限重算与塌 0 兜底；设为 `false` 退化为仅检负值 |
| `verify_variables` | `true` | 变量系统忠实复算开关（4.6 token 链已适配：检测 + 回写饱和值；变量效果调用很少，开销可忽略，默认开） |
| `diag_recompute_calls` | `0` | 诊断开关：打印前 N 次上限重算中间量与 HULLMAP 偏移扫描（**会绕过早退热路径，排查完请改回 0**） |
| `diag_modifier_calls` | `0` | 诊断开关：统计 `ApplyModifierMult` 的 ModifierType 直方图（有逐调用原子加开销，默认关） |
| `log_recompute_mismatch` | `false` | 记录「重算 ≠ 游戏但未触达回写闸门」的 NOTE 日志（默认关） |
| `collapse_log_limit` | `64` | 「加算溢出塌成 0」事件最多记录多少条（按 design 指针去重防刷屏） |

**日志**：写入 `<插件目录>\logs\satfix.log`，以 `_wsopen_s(..., _SH_DENYNO)` 打开确保游戏运行期间可随时读取，上限 `20000` 行，首行打印版本、构建模式、游戏路径、PE 时间戳校验与 14 组进程内自检结果。

---

## 6. 构建、自测、探针与发布

### 6.1 编译与自动化自测

需要 VS 2022 Build Tools（x64 C++ 工具链 + Windows SDK）与 Python 3。

```powershell
cd satfix-win

.\build.ps1                # 影子模式（默认，开发/观察用）
.\build.ps1 -Replace       # 回写模式（发布版必须用这个）
.\build.ps1 -TestOnly      # 仅跑 winhook 单元测试
```

构建脚本串联 4 项自动化验证，任一失败即中止：
1. `test_winhook.exe` —— hook 引擎合成机器码测试（含 rel8 加宽、线程挂起补丁、卸载重装、坏目标拒绝）；
2. `test_stl_fix_win.exe` —— 128 位定点饱和算术离线对拍 + `satfix_decision.hpp` 14 组自检向量；
3. `test_load_plugin.exe` —— 在宿主进程中 `LoadLibrary` 验证 `DllMain` 返回时长、目录定位、日志共享可读性与导出统计接口；
4. `tools/check_plugin_pkg.py` —— 按插件手册 §13 校验 `dist\satfix\` 清单合法性与包内容纯净度（不含 `--exe` 时 24 项，带 `--exe` 时 25 项）。

> 注意：更新 DLL 前请先退出正在运行的 `stellaris.exe`，否则复制覆盖 `plugin\satfix.dll` 会因文件占用失败。

### 6.2 本地联调与活体探针

```powershell
$stl = "$env:LOCALAPPDATA\Programs\Stellaris Launcher\stl.exe"
& $stl plugin install "$PWD\plugin" --link
& $stl plugin enable satfix
& $stl launch
Get-Content .\plugin\logs\satfix.log
```

**活体探针**（仅在排查纯函数 ABI 或验证回写端到端链路时使用，正常游玩切勿开启）：

```powershell
$env:SATFIX_WIN_FORCE = '1'
& $stl launch
# 初始化末尾会使用边界值直接探测 GetRounded / to_fp15 / GetRounded(fp15) / RoundTo / Atan2 / Sqrt / SafeSqrt
```

`SATFIX_WIN_FORCE=1` 同时用于离线测试绕过进程名检查（仍保留 PE 时间戳与序言签名校验）。

### 6.3 打包与发布

```powershell
cd satfix-win
.\build.ps1 -Replace
.\tools\package_release.ps1
```

打包脚本校验构建模式为 `write-back`、包内不含 `config\`/`logs\`、提取 `RELEASE_NOTES.md` 中对应的 `## v<version>` 段落，在 `release\` 下生成 `satfix-v<version>.zip`、`.sha256` 与 `.zip.notes.md`，并打印 `gh release create` 命令。

---

## 7. 游戏更新后的重定位

游戏更新后第一步运行漂移检查：

```powershell
python tools\gen_targets_win.py --check
```

若报告时间戳或序言签名不匹配，请按 [`tools/relocate/README.md`](tools/relocate/README.md) 执行跨版本重定位，并更新：
1. `tools/gen_targets_win.py` 的目标 RVA 与证据 → 重新生成 `src/satfix_targets_win.generated.hpp`；
2. `src/sat_guard_win.cpp` 中的 ModifierType 枚举、元数据表地址、船级表地址及必要安全闸；
3. `plugin/stl-plugin.json` 的 `version` 与 `game.exe_timestamps`；
4. `RELEASE_NOTES.md` 新增对应版本说明。

---

## 8. 插件规范（v2）合规对照

| 手册条款 | 规范要求 | 本插件实现 |
| --- | --- | --- |
| 6.1 | `DllMain` 极简，只创建线程 | 仅 `DisableThreadLibraryCalls` + `CreateThread` + `CloseHandle` |
| 6.2 | 从模块地址定位插件目录 | `GetModuleHandleExW(FROM_ADDRESS)` + `GetModuleFileNameW` |
| 6.3 | 引擎函数仅在游戏主线程调用 | 自有线程只做 mtime 检查；重活由主线程泵执行 |
| 6.4 | 原始内存读取带 SEH；不依赖 Linux 偏移 | `whk::safe_read` / `fast_read`；偏移全部在 Windows 侧独立验证 |
| 6.5 | 与其他插件共存，必须调用原函数 | 全部通过 `TypedHook::call()` 经蹦床转发，不恢复他人钩子 |
| 6.6 | 永不自行卸载 | 生产路径无 `FreeLibraryAndExitThread` |
| 6.7 | `/MT` 静态运行库、x64、不弹控制台 | `/MT`、x64、无 `AllocConsole`、仅导入 `KERNEL32.dll` |
| 7 | 双层版本检查 | 清单 `game.exe_timestamps` + DLL 校验 PE 时间戳与 16B 序言签名 |
| 8 | 配置读取、内置默认、热重载 | 读 `config\satfix.ini`，缺失走默认值，每 2 秒检查 mtime 热重载 |
| 9.1 | 日志写入 `logs\`、运行中可读、有行数上限 | `_wsopen_s` + `_SH_DENYNO`（经实测兼容宿主同时读，见注），上限 20000 行 |
| 10.1 / 13 | 发布包不含 `config\`/`logs\` 与构建产物 | `build.ps1` 组装 `dist\satfix\` + `check_plugin_pkg.py` 与 `package_release.ps1` 双重把关 |

> 注（手册 9.1 实测调整）：手册建议 `_wfsopen(..., _SH_DENYWR)`，但在实机宿主测试中 CRT `_SH_DENYWR` 会对外部读者返回 `EACCES`；改用 `_wsopen_s(..., _SH_DENYNO)` 配合 `test_load_plugin` 共享可读断言确保行为满足手册意图。

---

## 9. 当前已知限制

1. **4.6.0 两项降级已处理**（原 0.5.0 的主动降级）：
   - `ship_size_max_hp`：`CShipSize` 的 `max_hitpoints` 偏移经实机反扫复核为 `+0x6f0`（4.5.3 的 `+0x6b8` 在 4.6.0 已失效），回写已恢复（`kShipSizeWriteEnabled = true`，仅负值触发）；
   - `var_multiply` / `var_add`：4.6 token 键控链已适配，`kVarShadowSupported = true` 恢复忠实复算，`kVarWriteEnabled = true` 回写饱和值；判据 `v1!=sat` 经 800 万组对拍证明完备无假阳（见 §4.3）。
2. **上限重算建模边界**：
   - 护盾/装甲的条件性船级修正（`0x1d4/0x1d5`、`0x1d2/0x1d3`）因依赖 `CFleet` 领土状态而采用乐观累加，由保守回写闸门兜底不误改；
   - 船体上限未建模三段条件性加法修正，重算偏小但方向安全；理论上若存在「未死舰船且真值为负」的极端情况会出现 `sat != v && v < 0` 窗口，按实机裁定暂不额外收紧（详析见 [`docs/ENGINEERING_NOTES.md`](docs/ENGINEERING_NOTES.md)）。
3. **仅覆盖非内联关口**：Windows 反编译中 `/ 100000` 展开逾 7000 处，内联副本无法 hook。
4. **物理天花板**：封顶值固定为 `INT64_MAX`（约 92.2 万亿游戏单位），受限于游戏自身的 64 位定点表示。
5. **未测试多插件并发**：本机仅在单插件环境下完成长局实机验证。
