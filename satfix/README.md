# satfix —— Stellaris 定点算术饱和守卫（Linux）

Linux x86-64 下的 `LD_PRELOAD` 共享库实现（`sat_guard.so`），依赖 [`../hooklib/shk.hpp`](../hooklib/shk.hpp) 按 mangled 符号名拦截游戏关键算术与结算函数，并在越界时提供饱和参考值。

> **平台同步状态说明**：本目录当前基线为 **Cygnus v4.5.2**（版本串 `v4.5.2  32709cf254181b032b1b309a6ea09776`），覆盖 **19 个游戏函数目标 + 6 个辅助函数 + 1 个可选 ImGui 调试窗口**。Windows 侧后续在 v0.3.x–v0.5.0 新增的 `damage_per_day`、`ship_size_max_hp`、装甲/船体完整重算配方（含舰船等级修正表与塌 0 封顶）及 Cygnus v4.6.0 适配尚未合入本目录。

---

## 1. 目录与文件

| 文件 / 目录 | 作用 |
| --- | --- |
| `sat_guard.cpp` | 插件本体：19 个目标 detour、6 个辅助函数解析、心跳统计与 `/proc/self/exe` 进程过滤 |
| `stl_fix.hpp` | 游戏三个定点方言的适配与精确饱和参考实现（基于 `EirinMath`） |
| `satfix_targets.generated.hpp` | **自动生成，勿手改**（19 个目标 + 4 个变量系统辅助函数的 mangled 名与兜底地址） |
| `debug_ui.hpp` | 可选 ImGui 调试窗口（实验性，见 [`docs/target_weight_debug.md`](docs/target_weight_debug.md)） |
| `test_stl_fix.cpp` | 离线算术对拍程序（含随机样本与边界向量，必须 `failures=0`） |
| `test/run_abi_check.sh` | ABI 回归脚本：用假游戏符号验证 detour 不写坏返回值、安全输入零误报 |
| `build.sh` | 一键构建：读配置 → 检查地址漂移 → 编译对拍与 `sat_guard.so` → 跑 ABI 回归 |
| `tools/configure.sh` | 自动探测或指定群星目录，生成本地 `satfix.conf`（已 gitignore） |
| `tools/find_stellaris.py` | 按环境变量 / `satfix.conf` / Steam `libraryfolders.vdf` 定位 `stellaris` |
| `tools/gen_targets.py` | 通过 `nm` / `nm -D` 解析符号地址并生成 `satfix_targets.generated.hpp` |
| `tools/fetch_eirin.sh` | 拉取 `EirinMath` Release 源码包至 `third_party/` |
| `third_party/EirinMath-1.5.2/` | 上游定点数学库头文件（MIT，见 [`third_party/README.md`](third_party/README.md)） |

---

## 2. 定点方言与溢出机制

基于 Cygnus v4.5.2 Linux 反编译确认，Stellaris 内部使用三种 64 位定点表示：

| 游戏类型 | 存储 | 进制 | `1.0` 的存储值 | 乘法形式 |
| --- | :---: | :---: | :---: | --- |
| `CFixedPoint` | `int64` | 十进制 | `100000` | `(v * m) / 100000`（带拆分回退） |
| `fpml::fixed_point<long long,48,15>` | `int64` | 二进制 | `2^15`（`0x8000`） | `(v * m) >> 15` |
| `fpml::fixed_point<long long,56,7>` | `int64` | 二进制 | `2^7`（`0x80`） | `(v * m) >> 7` |

两种 `fpml` 方言与 `eirin::fixed_num` 编码完全一致；十进制 `CFixedPoint` 由 `stl_fix.hpp` 适配。注意二者取整方向不同：`fpml` 的算术右移为向下取整，而 `CFixedPoint` 的 `/ 100000` 为向零截断，负数时可能相差 1 ULP，参考实现已分别处理。

### 乘法拆分路径与 200 万组实测结论

`CFixedPoint` 乘法并非单一路线的 `(a * b) / 100000`，而是先判定安全域再拆分：

```cpp
if (|v| <= 3037000499 && |m| <= 3037000499)   // 中间积一定不超出 int64
    return (v * m) / 100000;
else {
    X = max(v, m); Y = min(v, m);             // 有符号比较
    return ((X % 100000) * Y) / 100000 + (X / 100000) * Y;
}
```

200 万组随机离线对拍结果：
- **安全域内**（199 万组）：游戏原式与饱和实现 100% 逐位一致；
- **越界域**（61.9 万组出现分歧）：
  - **(a) 真值本身超过 `int64`**（`|v · m| > 9.2e23`）：引擎直接回绕，饱和值为正解；
  - **(b) 真值可表示但拆分首项 `(X % 100000) * Y` 先溢出**（约 11.9 万组，需 `|Y| > 9.2e13`）：引擎本可算对却算错。

### 已确凿的纯函数溢出与安全反例

- **必现溢出**：`CFixedPoint::GetRounded() const` 实现为 `x >= 0 ? (x + 50000) / 100000 : -((50000 - x) / 100000)`。当 `x = INT64_MAX` 时，`x + 50000` 溢出，游戏返回 **`-92233720368547`**，饱和正确值为 **`+92233720368547`**（见 `test_stl_fix` 第 6 节）。
- **证明安全**：`CFixedPoint::operator fpml::fixed_point<...,15>()` 的目标实数上限 `2^48 ≈ 2.8e14` 大于 `CFixedPoint` 上限 `9.2e13`，不会溢出，保留该钩子作回归验证。

---

## 3. Hook 目标清单（19 个目标 + 6 个辅助函数）

`CFixedPoint` 的 `operator+ - * /` 全部内联（反编译中 `/ 100000` 展开 2551 处），无法整体替换，只能守住关口。`sat_guard.cpp` 当前包含 19 个游戏目标：

| # | Key | 目标函数 | 策略 | 说明 |
| :---: | --- | --- | :---: | --- |
| 1 | `apply_mul_cfx` | `CModifier::ApplyModifierMult(CFixedPoint&, ...)` | EXACT | 乘法修正主出口；in-place 改写并返回实际倍率，无需解析 `CModifier` 内部结构 |
| 2 | `apply_mul_fp15` | `CModifier::ApplyModifierMult(fpml<...,15>&, ...)` | EXACT | 同上，乘法在 2^15 编码上执行 |
| 3 | `cfx_get_rounded` | `CFixedPoint::GetRounded() const` | EXACT | 修复 `x ± 50000` 溢出 |
| 4 | `cfx_get_rounded64` | `CFixedPoint::GetRounded64() const` | EXACT | 函数体与 #3 完全相同 |
| 5 | `cfx_to_fp15` | `CFixedPoint::operator fpml<...,15>() const` | EXACT | sret 返回（`RDI=返回槽, RSI=this`）；理论不溢出，作验证用 |
| 6 | `var_multiply` | `CMultiplyVariableEffect::ExecuteActual(CEventScope&) const` | EXACT | 调用 4 个变量 helper 读回 `v0` / `m` 做饱和复算与回写 |
| 7 | `var_add` | `CAddVariableEffect::ExecuteActual(CEventScope&) const` | EXACT | 同上，变量加法饱和复算与回写 |
| 8 | `shield_max` | `NShipUtil::CalcMaxShieldHitPoints` | EXACT | 复用 `GetCurrentGrowthStage` / `GetModifierValue` 饱和重算并等值比对（缺 helper 时退化为负值置 0） |
| 9 | `cfx_safe_sqrt_int` | `CFixedPoint::SafeSqrt(long long)` | INPUT_GUARD | 防止 `p * 100000` 溢出（`p > 92233720368547`）；依赖 `shk` 的 rel8→rel32 加宽 |
| 10 | `cfx_sqrt` | `CFixedPoint::Sqrt() const` | INPUT_GUARD | 负输入在原实现会被当作巨大无符号数迭代；回写模式下按 0 处理 |
| 11 | `cfx_safe_sqrt` | `CFixedPoint::SafeSqrt() const` | OBSERVE | 记录负输入 |
| 12 | `cfx_round_to` | `CFixedPoint::RoundTo(CFixedPoint const&)` | OBSERVE | 记录 `divisor == 0` 与 `v + divisor/2` 溢出 |
| 13 | `cfx_atan2` | `CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&)` | OBSERVE | 记录参数平方可能溢出的量级 |
| 14 | `cfx_get_rounded_fp15` | `CFixedPoint::GetRounded(fpml<...,15> const&)` | OBSERVE | 记录换算回十进制会溢出的量级 |
| 15 | `mpe15` | `NCombatRules::CalcMilitaryPowerExponent(fpml<...,15>, ...)` | OBSERVE | 舰队实力指数（pow 链），记录中间积越界风险 |
| 16 | `mpe7` | `NCombatRules::CalcMilitaryPowerExponent(fpml<...,7>, ...)` | OBSERVE | 同上，fp7 编码 |
| 17 | `diplo_weight` | `CPopJob::CalcDiplomaticWeight(CPopGroup const&) const` | OBSERVE | 外交权重不可能为负；记录负值或极端越界 |
| 18 | `armor_max` | `NShipUtil::CalcMaxArmorHitPoints` | 退化兜底\* | 暂未填入装甲专属偏移/type，走退化路径（结果为负时记 EVENT，回写模式置 0） |
| 19 | `hull_max` | `NShipUtil::CalcMaxHitPoints` | 退化兜底\* | 同上，暂走退化路径（避免套用护盾参数导致误判） |

**辅助函数（只解析调用，不 hook）**：
- 变量系统（定义在 `SATFIX_HELPERS`）：`AccessVariablePointer`、`CVariables::GetVariable`、`CVariables::SetVariable`、`CFixedPointVariableValue::GetValue`；任一解析失败则自动退化为纯透传计数。
- 上限重算（`sat_guard.cpp` 运行时动态解析）：`CShipSize::GetModifierValue`、`CBaseDesignImplementation::GetCurrentGrowthStage`。（注：`CShipSize::GetName` 已禁止在 hook 中调用，因其在 `CPdxTaskScheduler` 工作线程并发调用非线程安全的本地化池会导致 SEGV。）
- 可选调试模块：`debug_ui.hpp` 通过 hook 游戏内置 `ImGui::NewFrame` 绘制 `debug_target_weight` 窗口（缺任一 ImGui 符号即静默停用）。

---

## 4. 配置、构建与运行

所有脚本不硬编码游戏路径，配置优先级为：**环境变量 > `satfix.conf` > Steam 库自动探测**。

### 4.1 配置游戏路径（首次执行一次）

```bash
cd satfix
./tools/configure.sh                    # 自动探测 Steam libraryfolders.vdf 并生成 satfix.conf
./tools/configure.sh /path/to/Stellaris # 或手动指定目录
./tools/configure.sh --show             # 查看当前生效配置
./tools/configure.sh --clean            # 删除 satfix.conf
```

临时覆写路径（无需修改配置）：

```bash
BIN=/other/path/stellaris ./build.sh
EIRIN_INC=/path/to/EirinMath/include ./build.sh
```

### 4.2 构建与离线验证

```bash
./build.sh              # 影子模式（默认：只观测记日志，绝不改数值）
./build.sh replace      # 回写模式（检出问题时写回饱和值）
GEN=1 ./build.sh        # 强制重新生成 satfix_targets.generated.hpp

./test_stl_fix          # 运行离线对拍，必须 failures=0
```

`build.sh` 会自动执行三件事：
1. 调用 `tools/gen_targets.py --check` 检测地址漂移（漂移则自动重新生成）；
2. 编译 `test_stl_fix` 与 `sat_guard.so`；
3. 自动运行 `test/run_abi_check.sh`（使用假游戏符号做 ABI 回归，防止类似 `operator fpml` 的 sret 签名错配），失败即中止构建。

### 4.3 运行与环境变量

```bash
cd "$(dirname "$(python3 tools/find_stellaris.py)")"
LD_PRELOAD=/abs/path/to/satfix/sat_guard.so ./stellaris 2> /tmp/satfix.log

# Steam 启动选项：
#   LD_PRELOAD=/abs/path/to/satfix/sat_guard.so %command%
```

支持的运行时环境变量：

| 环境变量 | 说明 |
| --- | --- |
| `SATFIX_HEARTBEAT=<N>` | 每累计 N 次调用向 stderr 输出一次分类计数与累计溢出数（默认关闭） |
| `SATFIX_MAX_HP_CAP=<单位>` | 自定义上限退化阈值（单位为游戏单位，默认 `1e6` 游戏单位） |
| `SATFIX_TARGET_WEIGHT=1` | 启动时自动打开 `debug_target_weight` ImGui 调试窗口 |
| `SATFIX_VERBOSE=1` | 打印跳过非游戏子进程及辅助函数解析地址的详细日志 |
| `SATFIX_FORCE=1` | 绕过 `/proc/self/exe` 进程名检查（仅供离线 ABI 回归测试使用） |

> **子进程静默过滤**：通过包装脚本（如启动器脚本）传递 `LD_PRELOAD` 时，`bash`/`cp`/`rm` 等子进程会继承该环境变量。`sat_guard.so` 会检查 `/proc/self/exe`，非 `stellaris` 进程立即静默退出，不污染日志。

---

## 5. 日常验证与维护

1. **离线对拍**：`./build.sh && ./test_stl_fix`，确认 `failures=0` 且 ABI 回归通过。
2. **冒烟检查**：查看 stderr 确认全部目标均打印 `hooked ...`，以及运行时出现 `首次调用: <名称>`（区分「装上钩子」与「代码路径确实被执行」）。
3. **影子观察**：先用影子模式跑高倍率后期存档，检索日志：
   ```bash
   grep -c EVENT /tmp/satfix.log
   grep EVENT /tmp/satfix.log | sort | uniq -c | sort -rn | head
   ```
   确认检出行为符合预期、备份存档后再切换 `./build.sh replace`。
4. **游戏更新后**：`./build.sh` 会自动运行 `tools/gen_targets.py --check` 并在漂移时重建头文件。也可手动跑 `python3 tools/gen_targets.py --list` 检查是否有符号被 LTO 消除（`MISS`）。
5. **更新 EirinMath**：运行 `./tools/fetch_eirin.sh [版本|--list]`。

---

## 6. 已知限制

- **仅作用于非内联关口**：内联展开的定点运算副本不受 hook 影响。
- **平台滞后**：本目录目前停留在 4.5.2，`armor_max`/`hull_max` 尚未建模专属重算配方，亦未同步 Windows 侧的 `damage_per_day`、`ship_size_max_hp` 与 4.6.0 适配。
- **安装非线程安全**：`shk` 未做线程挂起式补丁，依赖全局对象构造时机在游戏主循环启动前完成安装。
- **ABI 依赖引擎约定**：`ApplyModifierMult` 影子复算依赖原函数返回实际倍率这一行为（4.5.2 反编译确认），若未来引擎修改该语义需同步调整。
- **无图形渲染侧干预**：Linux 版 Stellaris 4.5.2 仅使用 OpenGL（`ldd` 无 `libvulkan`，二进制中的 Vulkan 符号仅来自 SDL2 自带代码），本项目只作用于 CPU 定点算术。
