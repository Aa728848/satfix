# debug_target_weight：ImGui 索敌权重窗口

## 结论先说：不需要注入 ImGui

**群星自带 ImGui**，OpenGL3 后端，而且符号全部导出（`nm -C | grep -c ImGui` = 1134）。
所以"注入 ImGui"这件事不存在——我们只要 hook 它每帧的 `NewFrame`，在它之后画自己的窗口。

顺带纠正一个常见误解：游戏里那个 `imgui` 控制台命令（`OnExecute_ImGui` @0x2c4e9a0）
是它自己的一套 debug UI 注册表（`SImGuiSubCommandEntry` / `SImGuiUiEntry`），
和我们要加的窗口是两回事；我们不必去改它的表。

### 用到的 ImGui 入口（mangled 名已核实）

| 符号 | 地址 |
| --- | --- |
| `_ZN5ImGui8NewFrameEv` | 0x3f1d620 |
| `_ZN5ImGui5BeginEPKcPbi` | 0x3f22680 |
| `_ZN5ImGui3EndEv` | 0x3f297b0 |
| `_ZN5ImGui15TextUnformattedEPKcS1_` | 0x3f93510 |
| `_ZN5ImGui9SeparatorEv` | 0x3f96d70 |
| `_ZN5ImGui8CheckboxEPKcPb` | 0x3f95bc0 |
| `_ZN5ImGui11SmallButtonEPKc` | 0x3f94910 |
| `_ZN5ImGui17SetNextWindowSizeERK6ImVec2i` | 0x3f22650 |

`ImGui::NewFrame()` 在游戏里只有一个调用点，位于 `NImGuiWrapper::ImGuiNewFrame`（反编译 8570241），
hook `ImGui` 自己的 `NewFrame` 比 hook 那个 wrapper 更稳（不受 LTO 影响）。

## 已实现（`debug_ui.hpp`）

* hook `ImGui::NewFrame` → 调原函数 → 画窗口 `debug_target_weight`
* 窗口内容：标题、两个勾选框、`立即计算` 按钮、数据区
* 默认值按需求：**手动触发**（定期计算默认不勾）+ **不显示组件级权重**（默认不勾）
* 开关：环境变量 `SATFIX_TARGET_WEIGHT=1` 会在启动时把窗口打开
* 任何一个 ImGui 符号解析不到 → 整个模块不启用，打印一行原因，**不影响游戏**

```bash
SATFIX_TARGET_WEIGHT=1 LD_PRELOAD=./sat_guard.so ./cream.sh ./stellaris
```

## TODO 1：控制台命令 `debug_target_weight`

游戏的控制台命令注册机制已经找到，样板在 `SetupLocalizationConsoleCommands()`（反编译 8694035）：

```c
CConsoleCmdManager* mgr = CConsoleCmdManager::_pInstance;          // @0x6178878
if (!mgr) { CConsoleCmdManager::CreateInstance(); mgr = _pInstance; }   // @0x4221790
CConsoleCmd::SCommandData data;                                     // 0xa8 字节
memcpy(&data, &DAT_0551c7b0, 0xa8);                                 // 从静态模板拷
CConsoleCmdManager::AddCommand(mgr, &data);                         // @0x4221850（按引用传）
```

两条可选路线：

1. **抄模板**（推荐）：把现有命令（比如 `imgui`）的 `SCommandData` 拷一份，
   改掉 name 字段与 handler 指针，再 `AddCommand`。避免逆整个 0xa8 布局。
   需要先定位 `imgui` 命令的静态 `SCommandData`（`DAT_0551c7b0` 这类地址之一）。
2. **自己填结构**：要先逆清 `SCommandData` 的字段（可用
   `CConsoleCmd::GetCommandSyntaxDesc` @0x429c360 与 `CopyToNewCommandStructure`
   @0x429c680 反推），成本高。

handler 签名是固定的：`CConsoleCmd::SResult OnExecute_XXX(CPdxArray<CString,int> const&)`，
我们只关心"有没有参数"，返回"成功"。命令里切换 `satfix_ui::g_window_open` 即可。

## TODO 2：索敌权重数据源（主要工作量）

候选函数（都已定位）：

| 函数 | 地址 |
| --- | --- |
| `CWeaponComponentTargeting::ComputePotentialTargetScore(CWeaponComponent const&, SShipComponentMicroUpdateConstData const&, SSinglePotentialShipData const&, SSinglePotentialTargetData const&)` | 0x208b0f0 |
| `CShipTargeting::ComputePotentialTargetScore(CShip const*, SSinglePotentialShipData const&, SSinglePotentialTargetData const&, CFixedPoint&, bool, CString*)` | 0x2088d60 |

障碍是**两个入参结构**：`SSinglePotentialShipData` / `SSinglePotentialTargetData`
（以及武器的 `SShipComponentMicroUpdateConstData`）的布局还没逆。

建议的推进顺序：

1. 找 `CWeaponComponentTargeting` 的调用点（战斗微更新里生成候选目标的地方），
   从那里反推这两个结构的字段含义与填充来源；
2. 先只做**舰船级**（`CShipTargeting::ComputePotentialTargetScore`），
   组件级留到第二步——正好对应"默认不显示组件权重"的默认值；
3. 数据来源用"当前选中舰队 + 其敌对舰队"：`CFleet` 的舰船数组、
   `CCountry::IsHostileCached` 之类的现成函数（前面战斗分析里都见过）。

放一个**只读、每帧最多算一次**的约束：定期计算默认关闭，手动按钮触发一次；
勾了"定期计算"才每 N 帧算一次（N 待定，建议 ≥ 60 帧，避免影响帧率）。

## 需要你配合的事

* 晚上测的时候先只验证**窗口能不能出来**（`SATFIX_TARGET_WEIGHT=1`），
  确认控件能点、能勾、不崩、不掉帧 —— 这一步与数据源无关，先打通渲染链路；
* 如果窗口出不来，把 stderr 里那行 `ImGui 入口没解析全` 或 `hook ImGui::NewFrame 失败`
  发我（说明符号名/调用时机需要调整）；
* 数据源部分我需要你提供一条**具体场景**（哪个存档、哪场战斗、想看哪两方的权重），
  我按那条链路去逆结构，比盲逆快得多。
