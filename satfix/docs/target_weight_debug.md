# debug_target_weight：实验性 ImGui 索敌权重窗口（Linux）

> 本模块为 `satfix/`（Linux 侧）的实验性调试功能，位于 [`../debug_ui.hpp`](../debug_ui.hpp)，仅在设置环境变量 `SATFIX_TARGET_WEIGHT=1` 时展开窗口。

---

## 1. 原理：直接复用游戏内置 ImGui

Linux 版 Stellaris 自带 ImGui（OpenGL3 后端）并完整导出符号（`nm -C | grep -c ImGui` = 1134），因此无需自行注入一套 ImGui，只需 hook `ImGui::NewFrame`，在原函数执行之后绘制自定义窗口即可。

> 注：游戏控制台命令 `imgui`（`OnExecute_ImGui`）对应的是引擎内部的 debug UI 注册表（`SImGuiSubCommandEntry` / `SImGuiUiEntry`），与直接调用导出的 ImGui 绘制 API 无关。

已核实的 ImGui 导出入口（Cygnus v4.5.2）：

| 符号 | 4.5.2 静态地址参考 |
| --- | :---: |
| `_ZN5ImGui8NewFrameEv` | `0x3f1d620` |
| `_ZN5ImGui5BeginEPKcPbi` | `0x3f22680` |
| `_ZN5ImGui3EndEv` | `0x3f297b0` |
| `_ZN5ImGui15TextUnformattedEPKcS1_` | `0x3f93510` |
| `_ZN5ImGui9SeparatorEv` | `0x3f96d70` |
| `_ZN5ImGui8CheckboxEPKcPb` | `0x3f95bc0` |
| `_ZN5ImGui11SmallButtonEPKc` | `0x3f94910` |
| `_ZN5ImGui17SetNextWindowSizeERK6ImVec2i` | `0x3f22650` |

`ImGui::NewFrame()` 在游戏内唯一调用点是 `NImGuiWrapper::ImGuiNewFrame`；直接 hook `ImGui::NewFrame` 可避免受 LTO 内联影响。

---

## 2. 当前已实现

- 拦截 `ImGui::NewFrame`，在原函数返回后渲染 `debug_target_weight` 窗口；
- 窗口包含标题、两个复选框（「定期计算」「显示组件级权重」，默认均不勾选）、「立即计算」按钮与数据显示区；
- 启动开关：
  ```bash
  SATFIX_TARGET_WEIGHT=1 LD_PRELOAD=/abs/path/to/satfix/sat_guard.so ./stellaris
  ```
- 安全降级：任一 ImGui 符号解析失败时，整个调试模块自动停用并打印一行日志，不影响游戏和主溢出守卫功能。

---

## 3. 待完成事项（TODO）

### TODO 1：注册游戏控制台命令 `debug_target_weight`

控制台命令注册机制参考 `SetupLocalizationConsoleCommands()`（4.5.2 反编译 8694035）：

```cpp
CConsoleCmdManager* mgr = CConsoleCmdManager::_pInstance;
if (!mgr) { CConsoleCmdManager::CreateInstance(); mgr = _pInstance; }
CConsoleCmd::SCommandData data;        // 0xa8 字节
memcpy(&data, &existing_template, 0xa8);
CConsoleCmdManager::AddCommand(mgr, &data);
```

可选实现路线：
1. **复制模板（推荐）**：拷贝现有命令（如 `imgui`）的静态 `SCommandData`，仅替换命令名与回调函数指针后注册，避免逆向完整 `0xa8` 结构；
2. **手动构造**：借助 `CConsoleCmd::GetCommandSyntaxDesc` 与 `CopyToNewCommandStructure` 逆出完整字段布局。

回调签名固定为 `CConsoleCmd::SResult OnExecute_XXX(CPdxArray<CString, int> const&)`，在回调中切换 `satfix_ui::g_window_open` 即可。

### TODO 2：接入索敌权重数据源

候选目标函数（4.5.2）：

| 函数 | 4.5.2 静态地址参考 |
| --- | :---: |
| `CShipTargeting::ComputePotentialTargetScore(CShip const*, SSinglePotentialShipData const&, SSinglePotentialTargetData const&, CFixedPoint&, bool, CString*)` | `0x2088d60` |
| `CWeaponComponentTargeting::ComputePotentialTargetScore(CWeaponComponent const&, SShipComponentMicroUpdateConstData const&, SSinglePotentialShipData const&, SSinglePotentialTargetData const&)` | `0x208b0f0` |

后续推进方向：
1. 从战斗微更新调用点反推 `SSinglePotentialShipData`、`SSinglePotentialTargetData` 与 `SShipComponentMicroUpdateConstData` 的字段布局；
2. 先接入舰船级权重计算（遍历当前选中 `CFleet` 及其敌对舰队，借助 `CCountry::IsHostileCached` 过滤），再补充武器组件级权重；
3. 严格只读并限频：默认仅手动按钮触发，定期刷新间隔建议 ≥ 60 帧，避免拖慢帧率。
