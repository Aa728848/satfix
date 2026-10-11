# satfix-win —— Stellaris 定点溢出守卫（Windows DLL 插件）

把 [`../satfix`](../satfix)（Linux 的 `LD_PRELOAD` 定点算术饱和注入）迁移到 Windows，
按 [`stellaris-launcher/docs/PLUGIN_HANDBOOK.zh-CN.md`](../../stellaris-launcher/docs/PLUGIN_HANDBOOK.zh-CN.md)
（插件规范 v2）做成合规的启动器插件。

发布版是回写模式：`build.ps1 -Replace` 编出来的 DLL 会在检出溢出时把数值改写回饱和值。
不带参数编出来的影子模式只观测、只记日志，是开发自测用的，不随发布包分发。

| 文件 | 作用 |
| --- | --- |
| `winhook.hpp` | `shk.hpp` 的 Windows/x64 移植：入口 5 字节 `E9 rel32` → relay → 蹦床 |
| `satfix128.hpp` | MSVC 上的 128 位中间量算术（`_umul128`/`_udiv128`，替代 GCC 的 `__int128`） |
| `stl_fix_win.hpp` | 定点饱和语义（`stl_fix.hpp` 的移植，去掉 eirin 依赖） |
| `src/sat_guard_win.cpp` | 插件本体：DllMain / 日志 / 配置 / detour / 主线程泵 |
| `src/satfix_targets_win.generated.hpp` | 自动生成，勿手改（RVA + 序言签名） |
| `test/test_winhook.cpp` | hook 引擎自测（合成机器码，25 项） |
| `test/test_stl_fix_win.cpp` | 定点算术离线对拍（57 项） |
| `test/test_load_plugin.cpp` | 插件管线自测（宿主 LoadLibrary，23 项） |
| `tools/win_dump_index.py` | 给 Windows 反编译 dump 建函数索引 / 按 RVA 取函数体 |
| `tools/win_fingerprint.py` | 用定点常量指纹在 110843 个函数块里筛候选 |
| `tools/gen_targets_win.py` | 生成目标表；`--check` 校验 RVA/签名是否仍匹配 exe |
| `tools/check_plugin_pkg.py` | 插件包合规检查（手册第 13 节可自动化的部分） |
| `plugin/` | 插件包：`stl-plugin.json` + `satfix.dll` + `defaults/` |

---

## 0. 当前状态

第 3、5、6 节写的是 0.1 那一轮之前的进度，目标数量和定位结论以本节为准。

### 0.0 本轮（0.2.0 发布）的四个实质变化

这一节是**当前状态**，下面 0.1.x 各节是历史证据记录（数字可能停留在当时那一轮）。
四个变化的详细证据分别在 0.1.12 ~ 0.1.15。

#### 变化 1：护盾/装甲/船体上限从「阈值观测」改成「忠实重算 + 回写饱和值」

旧实现 `detour_max_hp` 只做 `if (v < 0 || v > cap)` 的阈值检查，既不重算也不回写 ——
所以「溢出后变成 0 / 负数」这类症状它根本修不了。新实现（设计迁移自 Linux 版）改成：

- 用**游戏自己的原语**饱和重算上限，与游戏写回的值做**等值比对**，不相等 = 原版那一步 wrap 了；
- 重算链：`size = ship_size_of(design)` → `base = *(design + off)` →
  `base += modifier_value(size, mods, type_a)` → `add = modifier_value(size, mods, type_b)` →
  `factor = add + 100000` → `result = base × factor / 100000`。

三个函数各自的常量**由读 Windows 函数体得出，不是照抄 Linux**（巧合与 Linux 一致，但那是核对出来的）：

| | design 偏移 | 加算 type | 乘算 type | 条件性船级修正 |
|---|---|---|---|---|
| hull | `0x10` | `0x1e` | `0x1f` | 无（未建模） |
| shield | `0x130` | `0x2e` | `0x2f` | `0x1c8` / `0x1c9` |
| armor | `0x70` | `0x24` | `0x25` | `0x1c6` / `0x1c7` |

还有一张**按舰船等级索引**的额外乘算修正表，三个函数形状相同、只有表地址不同：
`bVar1 = *(byte*)(design + 0x468)`，表地址 shield `0x28167ac` / armor `0x2816774` /
hull `0x281673c`。**漏掉它会让重算系统性偏小** —— 实测 游戏 = 21304430712 而重算 =
1782290712（差 13 倍），这正是船体此前一直「重算 ≠ 游戏」的原因。注意这一段在游戏里是
**内联**展开的，结尾不做 `modifier_value` 内部那一项相加，所以不能直接复用辅助函数，必须自己扫表。

实机验证：三个目标 `sat == 游戏` 逐位一致（6023400000 / 6023399996 / 75000000 / 13808500 四例全中）。

#### 变化 2：「护盾塌成 0」的根因与修复

根因是三步，缺一不可（用户实测确认）：

1. 加算修正真值 > 9.2e13 游戏单位（= `INT64_MAX/1e5` = 92233720368547），游戏自己的 mul
   在拆分路径上 wrap 成**负数**；
2. `GetModifierValue` 对掩码类型有兜底 `if (v < 0) v = 0`（反编译 `FUN_140d29dd0`），整项被夹成 **0**；
3. 上限 = `(base + 0) × 倍率` = 0 —— 倍率再大也是 0。

用户原话「吃了一个 buff 计算大于 92 万亿溢出了」，与 `INT64_MAX/1e5 = 92233720368547` 精确吻合。

实测证据（同一存档、同一条 design 指针）：

| | 装甲加算 `0x24` | 护盾加算 `0x2e` | 护盾乘算 `0x2f` |
|---|---|---|---|
| 正常舰船 | 2861907747 | 2861907747（两者相同） | — |
| 出问题那台 | 11000000000 | **0**（被塌掉） | 1000000000000000（1e10 游戏单位 = 1e12%） |

修复判据：**加算读到 0 + 倍率 ≥ 1e7 倍 → 封顶到 `INT64_MAX`**。这条判据只对「值住在加算项」的
目标（护盾/装甲）生效 —— 船体的加算项**正常就是 0**，用同一条会误伤，已用 `add_carries_value`
标志按目标分别开关。

实机验证：护盾 `0` → `92233720368547`（用户截图确认），且只有 `CalcMaxShieldHitPoints` 触发，
船体/装甲零误报。日志形如：

```
EVENT CalcMaxShieldHitPoints 加算溢出塌成 0（倍率=1000000000100000 = 10000000001.00 倍）-> 封顶到 9223372036854775807 [已回写]
```

#### 变化 3：新增第 18 个目标 `damage_per_day`（设计师面板的「伤害」）

定位方法（踩过一次坑，值得记）：

- **第一版是错的**：按独占常量 `0xb50679d3` 全库搜，挑了行数最接近的 `FUN_1403c2910`（851 行）。
  实测打开舰船面板时它算的是「单件武器」的倍率（读到 24.5 / 19.5 这类小值），面板那个大值
  从不出现在它里面。
- **改正方法**：三个上限函数都在 `NShipUtil` 片区，伤害也该在附近。扫 `0xA00000..0xA20000`
  这 218 个函数，只看有定点乘法或调 `FUN_140d29f10`/`FUN_140d29dd0` 的，得到 `FUN_140a14c60`
  （614 行），紧跟 `CalcMaxSpeed(0xA14150)` 之后。
- **决定性判据：ModifierType 序列逐个相同**。Linux `CalcAverageDamagePerDay` 依次取
  `0x3a / 0x40 / 0x168 / 0x41 / 0x1d2 / 0x1d3 / 0x230`（7 个）；Windows `FUN_140a14c60` 是
  **完全相同的 7 个、相同顺序**。（先前那个错的只用了其中 3 个。）
- **溢出点**：L594-596 `lVar8 = (plVar10 * plVar13) / 100000` 是裸 64 位乘，没有饱和。
- **实机抓到**（同一函数连续三次调用）：`*ret = 2078190048`（20781.90，正常）→
  `*ret = 19158706009081.23`（wrap，EVENT 触发）。用户确认「去掉射速的 buff 肯定就正常了」。
- **ABI**：sret，`long long* fn(ret /*rcx*/, design /*rdx*/, mods /*r8*/, fleet /*r9*/,
  char /*栈*/, void* /*栈*/)`，与三个上限函数同形。

**修复**：`*r` 是函数的 sret 返回槽（`return param_1`），**专门放返回值**，不是共享结构字段 ——
写它不会碰到别的统计项。判据硬：伤害不可能为负，负值或 > 9.2e13 游戏单位必然是 wrap，封顶到
`INT64_MAX`。实机验证：伤害 `-4380077663777.92` → `92233720368547.75/秒`（用户截图确认）。

**「只影响显示，不影响实际伤害」的三条证据**（用户专门问过）：

1. 面板调度器 `FUN_1411519f0` 把结果写进**栈上临时槽 `local_res8`**，然后 `return 1`（状态码）——
   数值传不出去。同一个调度器里，船体/护盾/装甲/速度/伤害等六项是同一形态的独立调用
   （各对应一个 `param_1 + 0x6xx` 字段）。
2. 调用 `FUN_140a14c60` 的 8 个函数**全是 UI 层**（含 `HEADER`/`TOTAL_VALUE`/`VALUE`/
   `GROWTH_THRESHOLD_BASE_TOOLTIP` 这类工具提示串，或就是那个面板调度器）。**一个战斗函数都没有**。
3. 战斗伤害走 `TakeDamage`/`DealDamage` 那条完全不同的链，读的是武器组件原始值。

**顺带澄清的设计问题**：面板那一格本来就是「总和」（函数内 L576 `*param_1 = *param_1 + *plVar13`
就是组件累加），而 `CFixedPoint` 是 int64 定点，格式天花板就是 `INT64_MAX` ——「单组件上限 × N」
在数学上做不到，超过就立刻再 wrap。所以封顶值只能是 `INT64_MAX`（92 万亿游戏单位），这是物理天花板。

#### 变化 4：性能修复（用户反馈「过一天的时间变长、流畅度降低」）

两处开销：

1. **重算在正常舰船上纯属浪费**。所有回写分支都要求 `v <= 0`（塌成 0 需要 `add_in == 0`
   且 base 恒为 0 → 游戏值必然是 0；wrap 要求 `v < 0` 或 `v == 0`），而正常舰船 v 是正数
   （实测 6023399996 等）。热路径函数每局被调用百万到千万次，每次重算要 4~6 次游戏函数调用
   （含一次虚调用）+ 扫 46 项修正表。现在 `v > 0` 直接返回，开销降到一次比较。
2. **`safe_read` 每次都做 `VirtualQuery`（内核态切换）**。新增 `fast_read`：只用 SEH 兜坏指针，
   正常路径几乎零开销。热路径全部改用它（地址来自游戏传入的指针，可信）；来自我们解析的
   RVA / 猜测偏移的读**仍然必须**走 `safe_read`。

实测（心跳累计调用数，同一存档同一进程）：快路径 273,333 调用/秒 vs 慢路径 256,667 调用/秒。
用户主观确认：「优化以后 1 天的速度明显快很多」。

### 已实机验证过的部分

* Windows hook 引擎可用：合成机器码自测 25/25 通过（rel8 加宽、线程挂起式补丁、卸载后可重装、坏目标拒绝）。
* 定点饱和算术与 Linux 版语义一致：离线对拍 58/58 通过。
* 判定逻辑在真进程里自检通过：14 组向量表在游戏进程内跑，日志 `判定逻辑自检：全部通过`。
* **18 个目标**全部装上，且全部确认真被游戏代码调用（`共装上 18/18 个钩子（跳过 0）`）；
  6 个辅助函数签名校验 `6/6`；启动日志另报 `未定位 1`（已判定 Windows 侧无对应代码，非缺口）。
* `REPLACE=1` 回写路径也实机跑过（0.5），且这一轮拿到了**真实 EVENT**（不再只是「不崩」）。
* 一局后期 mod 存档的实测统计见 `EVIDENCE_live_gameplay.txt`（0.1 那轮，十七目标构建）：

  ```
  累计 23.9M 次调用（0.2.0 十七目标构建）：
      Atan2                          3652911
      ApplyModifierMult(cfx)         1457768   <- 主战场，数值放大的真正出口
      CalcMaxShieldHitPoints         1002320   <- 本轮新增
      CalcMaxArmorHitPoints          1002320   <- 本轮新增
      CalcMaxHitPoints               1002320   <- 本轮新增
      GetRounded/GetRounded64         149490
      add_variable                     15318
      Sqrt                              3188   <- 本轮新增
      SafeSqrt                          1173
      CalcDiplomaticWeight             390256   <- NDefines 名字法
      CalcMilitaryPowerExponent<15>   1625512   <- NDefines 名字法 + 编码判据
      CalcMilitaryPowerExponent<7>    1562356   <- 同上
      multiply_variable                 8595
      GetRounded(fp15)                  6337
      RoundTo                           4950
      ApplyModifierMult(fp15)              0   <- 该重载在此存档未被走到
  ```

  0.1 那一轮：正常游玩期间 0 条真实 EVENT，与 Linux 侧判断一致（原版量级离阈值极远，要 mod 把数值
  推到 ~9.2e17 才会溢出）。0 条 EVENT 是预期结果，并不说明钩子没装上，后者由首次调用
  心跳与自检排除。

  0.2 这一轮（18 目标构建）的实机日志：

  ```
  目标: 签名校验通过 18/18，未定位 1（见下），本构建适配 18
  辅助函数: 签名校验通过 6/6（变量系统 EXACT 可用）
  共装上 18/18 个钩子（跳过 0）  [REPLACE 已开]

  --- heartbeat: 100000 次调用，溢出 6770 次 ---
        GetRounded/GetRounded64              78
        ApplyModifierMult(cfx)               20968
        Atan2                                4
        CalcMaxShieldHitPoints               19507
        CalcMaxArmorHitPoints                19506
        CalcMaxHitPoints                     19507
        Sqrt                                 2
        SafeSqrt                             2
        CalcDiplomaticWeight                 100
        CalcMilitaryPowerExponent<15>        442
        CalcMilitaryPowerExponent<7>         9950
        CalcAverageDamagePerDay              9934
  ```

  这一轮 EVENT 有两条来源：`CalcMaxShieldHitPoints 加算溢出塌成 0` 与
  `CalcAverageDamagePerDay 伤害溢出 -> 封顶`（见 0.0 变化 2、变化 3）。日志上限 20000 行，
  事件按 design 指针限流（面板每帧都会重算同一个 design）。

### 0.1 十八个目标与它们的实机证据

策略分布：**EXACT 8 / INPUT_GUARD 1 / OBSERVE 9**（以 `src/satfix_targets_win.generated.hpp` 为准）。
另有 6 个辅助函数只解析地址、不装钩子；未定位 1 个（`cfx_safe_sqrt_int`，已判定 Windows 侧无对应代码）。

| 目标 | RVA | 策略 | 实机验到的 |
|---|---|---|---|
| `cfx_get_rounded` | `0x1B4C170` | EXACT | 3 条 EVENT，边界精确在 `x ≥ 9223372036854725808` |
| `cfx_to_fp15` | `0x1B4C0A0` | EXACT | 4 输入全匹配模型，0 分歧 |
| `apply_mul_cfx` | `0x36DF80` | EXACT | 一局内 145 万次调用（主战场） |
| `apply_mul_fp15` | `0x36E0A0` | EXACT | 已装上；该存档内 0 次（重载未被走到） |
| `cfx_round_to` | `0x1B4C1B0` | OBSERVE | 探针 `1234567,div1000→1235000,q1235`；实测 4950 次 |
| `cfx_atan2` | `0x1B4C2D0` | OBSERVE | 探针 `(1.0,1.0)→78539`(=π/4×1e5)；实测 365 万次 |
| `cfx_get_rounded_fp15` | `0x1B4C100` | OBSERVE | 实测 6337 次 |
| `var_multiply` | `0x1777F00` | **OBSERVE** | 实测 8595 次；SAMPLE 证明读回链自洽（0.1.4）。**当前策略是 OBSERVE** —— 见 0.1.4 的说明 |
| `var_add` | `0x1777800` | **OBSERVE** | 实测 13003 次；SAMPLE 三次 v0 递推自洽（0.1.4）。**当前策略是 OBSERVE** |
| `shield_max` | `0xA11D80` | **EXACT** | 实测 100 万次；本轮升级为忠实重算 + 回写（0.0 变化 1、2） |
| `armor_max` | `0xA12910` | **EXACT** | 实测 100 万次；同上 |
| `hull_max` | `0xA112A0` | **EXACT** | 实测 100 万次；同上 |
| `cfx_sqrt` | `0x1B489D0` | INPUT_GUARD | 探针 √1.0→1.00001、√100000→316.22927（误差 4.6e-6）；负值触发守卫 |
| `cfx_safe_sqrt` | `0x1B4C600` | OBSERVE | 探针 √100000→316.22790（误差 4.4e-7，比 Sqrt 更准） |
| `diplo_weight` | `0x838670` | OBSERVE | 实测 39 万次（用户实测最易溢出的那个） |
| `mpe15` | `0xA0A4A0` | OBSERVE | 实测 162 万次（fp15 舰队实力指数） |
| `mpe7` | `0xA0A610` | OBSERVE | 实测 156 万次（fp7 舰队实力指数） |
| `damage_per_day` | `0xA14C60` | **EXACT** | **本轮新增的第 18 个目标**；面板「伤害」负值 -> 封顶（0.0 变化 3） |

> 6 个辅助函数（只解析地址、不装钩子）：`access_var_pointer` `0x9F7DF0`、
> `cvars_get` `0x227390`、`cvars_set` `0x7AAE10`、`cfp_getvalue` `0x34D500`（变量系统用）；
> `ship_size_of` `0x30E990`、`modifier_value` `0xD29DD0`（**上限重算链用**，0.0 变化 1）。

### 0.1.2 本轮的方法突破：唯一常量集与调用者定位

前几轮靠函数体形状猜，屡屡失败（75 个同形状候选、293 个守卫对候选）。本轮换成两条可证伪
的路子，都成功了：

1. **唯一常量集**（用于 `armor_max` / `shield_max` / `hull_max`）。Linux 版体内含有 CShipSize
   修正类型表的索引常量（ModifierType 枚举值），三个函数各有一组互不相交的常量。把
   `0x15fec/0x15ff8/0x160a8` 三个常量同时作为检索条件扫过全部 110843 个函数块，命中数为 1，
   就是 `0xA12910`。shield/hull 用同样的办法各命中 1 个。两条独立签名互相印证（表偏移 +
   从 `param_2` 读的结构偏移，与 Linux 逐字相同）。
2. **helper 调用组合**（用于 `var_add`）。先拿已确证的 `var_multiply`，从它的调用点读出
   4 个 helper 的 RVA，再找同时调用这 4 个的函数。命中变量效果家族，其中不含乘法安全域
   常量的 26 行成员只有两个，读体区分加/减（`value + var` vs `var - value`）即可确定。

### 0.1.3 一个必须记下的教训：`var_multiply` 的旧 RVA 装错了函数

`0x00231640` 是错的。它的体内有 `type*0xb0 + 0x9c + DAT_142814390` 的 CModifier 类型表
掩码查表，并就地累加 `*(param_1+0x38)` 的 0x10 步长数组，那是 CModifier 惯用法，不是变量系统。

发现方式：Linux `CMultiplyVariableEffect::ExecuteActual` 里有一条独占诊断串
`multiply_variable: variable %s is not set for scoped %s '%s' at %s`。
按该串在 Windows dump 里检索，唯一命中 `0x1777F00`，其体形与 Linux 逐条对应
（4 个 helper 的调用序一一对上）。

教训是函数体看起来像（同常量、同惯用法）不等于身份。`0xb504f333/0x16a09e667` 这对常量
在 dump 里到处都是（乘法安全域判断），任何以它为核心的指纹都没有区分度。真正有区分度的
是独占字符串、类型表索引常量集、已确证函数的 helper 调用组合这三类。

### 0.1.4 变量系统打通了读回链（读回通了，但**策略仍是 OBSERVE**）

> ⚠️ **本节标题是历史措辞，结论已更正**：这一轮把 `var_add` / `var_multiply` 的读回链打通了
> （当时写成「升级成真 EXACT」），但 `src/satfix_targets_win.generated.hpp` 里这两个目标
> **当前是 `kObserve`**。降级理由（以 generated 头与 `gen_targets_win.py` 为准）：EXACT 依赖
> **先读到 `v0`** 再复算饱和加法/乘法，而 Windows 上 `v0` 的读取路径是
> `FUN_140227390` + 名字 `CString` 布局，尚未验证；贸然 EXACT 会写坏存档。先用 OBSERVE 计数、
> 看实机量级，确认 helper 语义后再升级。下面的 SAMPLE 证据仍然有效 —— 它证明的是**读回链自洽**，
> 不是「已经按 EXACT 回写」。

上一轮 `var_add` / `var_multiply` 还只能 OBSERVE，卡在读不回变量当前值。这一轮读回链通了：
辅助函数的 RVA 是从已确证目标的调用点读出来的，不是猜的。`var_multiply(0x1777F00)`
体内按 Linux 的调用序调用四个 helper，逐个对得上：

| Linux | Windows | ABI |
|---|---|---|
| `AccessVariablePointer(scope, name)` | `0x9F7DF0` | `longlong fn(scope, name)` |
| `CVariables::GetVariable(name)` | `0x227390` | `longlong* fn(vars+8, out, name)` |
| `CVariables::SetVariable(name, v)` | `0x7AAE10` | `void fn(vars, name, value)` |
| `CFixedPointVariableValue::GetValue(scope)` | `0x34D500` | `longlong* fn(this+0xf0, out, scope)` |

（`cvars_get` 的读偏移是 `entry + 0x38`，`cvars_set` 的写偏移是 `entry + 0x38`，两侧互为印证。）

两个关键偏移由读、写两侧互相印证得出：变量条目 +4 是「已设」标志（== -1 表示未设，
游戏按 0 参与运算），条目 +0x38 是 CFixedPoint 值（`GetVariable` 的读偏移与 `SetVariable`
的写偏移在反编译里是同一个数）。

这次的 0 条 EVENT 不能算证据：影子读法可能整体读错位置，那样也会永远一致。所以加了
有界 SAMPLE 日志（每个操作最多 3 行），实机拿到的是自洽链而不是空白：

```
SAMPLE add_variable      v0=0             d=100000 game=100000       sat=100000       一致
SAMPLE add_variable      v0=100000        d=100000 game=200000       sat=200000       一致
SAMPLE add_variable      v0=200000        d=100000 game=300000       sat=300000       一致
SAMPLE multiply_variable v0=7345573000000 d=100000 game=7345573000000 sat=7345573000000 一致
```

三次 `add_variable` 的 v0 依次是上一次的写回值（0 → 100000 → 200000），
证明读回链真的接在游戏状态上，而不是读了个常量槽。
（`v0=7345573000000, d=100000 → 7345573000000` 就是 ×1.0，量级也合理。）

### 0.1.5 本轮证伪的三条定位思路（留档，别再走）

1. Linux 里的立即数这类指纹对 MSVC 不可移植。`mpe15` 在 Linux 里有 `0x7fffffff8000` / `0xffffffffffff8000`（fp15 符号保留右移），在 Windows dump 里出现 0 次，MSVC 把 `(x>>15)` 编成 SAR 指令加事后掩码，不写立即数。同理 `mpe7` 的 `0x7fffffff80` 也是 0 次。
2. Linux 的成员偏移不能直接搬到 MSVC。`diplo_weight` 的 `+0x808` 且 `+0xec` 且 `+0xe0` 组合在 Windows 侧命中 0 个，已知的布局差异有 `+0xb8→+0xc0`、`+0xe8→+0xf0`。
3. 按间距找邻居不可靠。Linux `var_multiply`(91 行) 与 `var_add`(26 行) 相距 0xDF0，Windows 对应的两个函数体量不同（99 行 / 26 行），间距不可移植。

真正管用的三类判据是独占字符串（`var_multiply` 的
`multiply_variable: variable %s is not set…`）、类型表索引常量集（`armor_max` 的
`0x15fec/0x15ff8/0x160a8` 三常量同现，全库唯一）、已确证函数的 helper 调用组合
（`var_add`：先提取 4 个 helper RVA 再找同类），本轮全部命中唯一解。

### 0.1.6 `cfx_sqrt` / `cfx_safe_sqrt`：调用者法第二次奏效，外加一次 ABI 踩坑

定位沿用 `apply_mul_cfx` 那套靠调用者的办法。Linux 里调用 `CFixedPoint::Sqrt` 的只有
4 个函数，其中 `CalcDistance` 同时调用 `Sqrt` 与 `SafeSqrt`，且带独特常量
`0xf4241`(=1000001)。按该常量在 Windows 侧得到 3 个候选，其中一个含 CFixedPoint 专属
魔数 `0x29f16b11c6d1e109`，读体确认是 `CalcDistance` 同构体，它调用的 `FUN_141b489d0`
就是 `Sqrt`。再由 `Sqrt` 的调用者顺出 `FUN_141b4c600` = `SafeSqrt() const`
（常量 `0x2711`/10000/1000/2999999999 与 Linux 逐个对上）。

踩的坑是活体探针抓出来的：我把两个函数都按 `(out, src)` 写，`Sqrt` 是对的，`SafeSqrt`
反了。探针立刻暴露，它的返回槽一直是我预置的哨兵 `0x5A5A5A5A5A5A5A5A`
（= 6510615555426900570），五个输入全都返回同一个数。看函数体才发现 `Sqrt` 是
`*param_1 = result`（out 在 rcx），`SafeSqrt` 是 `*param_2 = result`（src 在 rcx、out 在 rdx）。

> 同一个类里的相邻成员，参数顺序不一定一致。必须逐个按函数体定签名，不能因为它们是兄弟
> 函数就类推。

修正后的探针数值（这才是 ABI 正确的证据）：

| 输入 | `Sqrt` | `SafeSqrt` | 真值 |
|---|---|---|---|
| 1.0 | 100001 | 100001 | √1 = 1.0 OK |
| 100000.0 | 31622927（误差 4.6e-6） | 31622790（误差 4.4e-7） | √100000 = 316.227766 |
| 1（=1e-5） | 0（走 `1 < x` 守卫） | 317（0.00317） | √1e-5 = 0.003162 OK |
| -1 | 0，INPUT_GUARD 触发 | 0 | OK |

`SafeSqrt` 比 `Sqrt` 更准，这正是它先缩放进安全域再算的设计目的。两个函数都返回真
平方根，身份与语义双双确证。

### 0.1.7 `cfx_safe_sqrt_int`：Windows 侧不存在这个函数（已内联）

Linux 版它只有 10 行：`if (p > 0) { x = p*100000; return SafeSqrt(&x); } return 0;`。
`Sqrt` 与 `SafeSqrt` 的全部调用者都已枚举并逐个读过体，没有任何一个是这个 10 行包装
（`SafeSqrt` 的 7 个调用者都是大函数，最小 43 行）。MSVC 把这种小包装直接内联进调用者
是常规做法。

所以 Linux 侧针对它的 INPUT_GUARD 在 Windows 上无处可装。这不是没找到，是确实不存在。
等价保护已被覆盖：内联展开后真正做 `p*100000` 的那一步，其结果要么进 `SafeSqrt`
（已装 OBSERVE）、要么进 `Sqrt`（已装 INPUT_GUARD）。

### 0.1.8 `diplo_weight`：NDefines 名字法（本轮第三个方法突破）

这是用户实测后期最容易溢出的目标，也是最难的一个。它在 Linux 里没有任何直接调用者
（只有 4 处提及，全是它自己），所以调用者法完全无效；按守卫密度筛出 24 个候选、
按结构偏移 `+0x808` 命中 0 个。

突破口是 Paradox 的 NDefines 名字字符串。这类名字（`DIPLOMACY_WEIGHT_POP_BASE` 等）
确实以明文存在于 exe 的 .rdata 里。流程是在 .rdata 里找到名字字符串的 VA，扫 .text 找
rip-relative 引用它的指令（每个名字只有 1 处），反汇编那处看到的是一个 5 指令 thunk：

```
mov rcx, rdx
lea r9,  [全局地址]        <- 该 define 的**存放位置**
lea rdx, ["NGameplay"]     <- 所属组
lea r8,  ["<define 名>"]
jmp <注册函数>
```

名字到全局地址的对应关系就这样被直接读出来了，不是猜的：
`DIPLOMACY_WEIGHT_POP_BASE → 0x143151010`、`DIPLOMACY_WEIGHT_POP_HAPPINESS → 0x143151008`。
接着在全部 110843 个函数块里找同时读这两个全局的函数，命中数为 1。

结果是 `FUN_140838670`，体形与 Linux 1177404-1177484 逐条对上：`param_3+8` 虚调用、
`param_1+0x18` 取 CJobType、`param_1+0xec` 计数 / `param_1+0xe0` 数组（这两个偏移与 Linux
完全相同）、`(arr)[i*2+1] * 100000`、`* DAT_143151010 / 100000`、`FUN_14067eec0`
（= `CPopGroup::HasHappiness`）、`* DAT_143151008 / 100000`、`*(param_3+0x8b0)` 再乘、
求和写回 sret。

顺带解答了上一轮的疑问：Linux 读 `param_10+0x808`，Windows 读 `param_3+0x8b0`，这就是
为什么按 `+0x808` 检索命中 0 个。MSVC 布局差异又一次得到实证。

> 可复用的方法：任何 Paradox 的 `NDefines::<组>::<名字>` 静态成员，都能用
> `.rdata 名字字符串 → .text 里的 thunk → r9 里的全局地址` 三步定位。这比函数体指纹可靠
> 得多，因为它读的是编译器自己写的元数据。

### 0.1.9 `REPLACE=1` 实跑 + 又一个真并发 bug

`REPLACE=1` 构建实机跑过：15/15 钩子（`[REPLACE 已开]`），3.5M 次调用，0 条 EVENT、
0 次 replaced，游戏全程稳定。

> 0 次 replaced 是正确行为，不是失效。正常游玩离 int64 溢出阈值差十几个数量级，回写
> 路径本来就该一次都不走。回写代码的正确性由离线对拍 58/58 + 判定自检 14 组覆盖，
> 实机这一趟验的是开着回写不崩、不写坏状态。

抓到的 bug 是日志并发交错，症状是日志里出现

```
      CalcDiplomaticWeight                 50986[satfix] --- heartbeat: ...
```

根因是 `log_line_raw` 早先是三次独立调用（`fputs` 前缀 / `fputs` 正文 / `fputc` 换行），
而 detour 跑在多个游戏线程上，两个线程会插在中间。上一轮只把正文拼成一块，前缀那步
仍是独立调用，所以没修干净。

修法是整行（前缀 + 正文 + 换行）先拼进一个缓冲，再一次 `fputs`；并加 `SRWLOCK` 让
行数检查加写入成为临界区，避免两线程同时越过行数上限，或同时用同一个缓冲。

验证：修后实机 0 条畸形行（`\d+\[satfix\]` 匹配数 = 0），心跳块完整。

### 0.1.10 `mpe15`/`mpe7`：把 NDefines 名字法做成通用工具

这两个目标前两轮完全卡住：调用者法无效（调用者不带独占字符串），常量法无效（Linux 的
`0x15bf1` 与 `0x7fffffff8000` 在 Windows 侧都是 0 次），递归判据无效（73 个自递归函数里
没有一个是它）。

本轮把 `diplo_weight` 用的 NDefines 名字法做成通用工具，一举破局：

1. 先把 thunk 解析器写对。关键 bug 是字符串地址必须经 RVA 到文件偏移转换，不能直接用
   `va - ImageBase`：`.rdata` 的 raw/virtual 对齐不同（本例差 0x2000），我最初正是踩了
   这个，得到的是垃圾名字。用已独立确证的 `DIPLOMACY_WEIGHT_POP_BASE/HAPPINESS` 做校准，
   解析器给出的 `0x143151010` / `0x143151008` 与前面两次独立确证完全一致，解析器可信。
2. 共提取 2369 个 (名字, 组, 全局地址) 三元组，含 31 个 `MILITARY_POWER*`，拿到
   `MILITARY_POWER_EXPONENT → 0x1431505B0`（组 = `NShip`）。
3. 唯一读它的函数 `FUN_140a08960` 把这个 define 当指数传给 `FUN_140a0a610`，那就是幂函数。
4. 用移位宽度判精度：`FUN_140a0a610` 是 `<<7`/`>>7`/`0x80`/`0x7f`，是 fp7，即 `mpe7`；
   紧邻的 `FUN_140a0a4a0` 是 `<<0xf`/`>>0xf`/`0x8000`/`0x7fff`，是 fp15，即 `mpe15`。

编码判定与 Linux 完全吻合：

| | Linux 掩码 | Windows 移位 |
|---|---|---|
| mpe15 | `0x7fffffff8000` / `0xffffffffffff8000` | `<<0xf` / `>>0xf` / `0x8000` |
| mpe7 | `0x7fffffff80` / `0xffffffffffffff80` | `<<7` / `>>7` / `0x80` |

两边都是处理负指数 → 调 log2 辅助 → 累加收敛，收敛条件同为 `while (sum != next + sum)`；
各自还有配套的 log2 辅助（mpe15 用 `FUN_140a0a770` fp15 版、mpe7 用 `FUN_140a0a840` fp7
版，成对）。

> ABI 踩坑第 4 次：Linux 是 `(out, 指数, 底数)`，Windows 是 `(out, 底数, 指数)`，顺序相反。

实机：`<15>` 162 万次、`<7>` 156 万次，都被真实战斗代码大量调用，0 条分歧。

### 0.1.11 收尾核查：三个缺口的真假 + 回写路径的端到端 A/B 证明

逐条核对 Linux 的 24 项与 Windows 的 21 项（Linux 表里第一项 `key` 是宏占位，不是目标）。
**这是 0.1 那一轮的数字**（当时 17 个目标 + 4 个辅助函数）；当前是 **18 个目标 + 6 个辅助函数**，
新增的 `damage_per_day` 与两个上限重算辅助函数见 0.0。
Linux 有、Windows 无的只有两个：

1. **`cfx_get_rounded64`：不是缺口，已覆盖。** 把 `0x1B4C170` 的前 24 字节机器码在整个镜像里做字节搜索，全镜像只出现 1 次。说明 MSVC 的 COMDAT 折叠把 `GetRounded` 与 `GetRounded64`（Linux 里是两个独立地址 `0x04230860` / `0x042308b0`）合并成了一份代码。所以那一个钩子同时覆盖两者，它本来就只有一份。
2. **`cfx_safe_sqrt_int`：已判定 Windows 侧无对应代码，不是缺口。**

   定位方式是：Linux 侧 `SafeSqrt(long long)` 唯一的真实调用点是 `MTTHModifyNumber` 的
   `case 0xf`（脚本 `sqrt` 运算符），该分支前有独占报错串
   `script_value/MTTH/weight field: Cannot square root a number that is negative at %s`。
   按该串在 Windows dump 里检索，唯一命中 `FUN_14033fd20`（Windows 的 `MTTHModifyNumber`）。

   读它的 `case 0xf`：

   ```c
   case 0xf:
     if (-1 < (longlong)*param_1) {                  // 非负才走
         puVar4 = FUN_141b4c600(param_1, &local_20); // = SafeSqrt(CFixedPoint const&)
         *param_1 = *puVar4;
         return 1;
     }
     ... "Cannot square root a number that is negative at %s"   // 负值 -> 报错，不算
   ```

   它直接把 `param_1`（一个 `CFixedPoint*`）的地址传给引用版 `SafeSqrt`，没有
   `p * 100000` 这一步。

   | | Linux | Windows |
   |---|---|---|
   | 调用形态 | `SafeSqrt(param_9)`，实参是整数 `long` | `FUN_141b4c600(param_1, …)`，实参是指针 |
   | 溢出点 | 函数内部做 `p * 100000` | 没有这一步 |

   `case 0xf` 里 `param_1` 本来就是定点格式，值已在格式内，所以编译器直接用引用重载，
   不需要整数到定点的换算，那个 `p*100000` 压根不生成。Linux 那条 INPUT_GUARD 保护的
   是一步 Windows 编译器根本不会生成的运算。

   而且 `case 0xf` 自己已有负值检查（负则报错返回，不计算），Linux 那个守卫要防的场景，
   游戏在本路径上已自行防护。真正的 `sqrt` 求值路径已被 `cfx_safe_sqrt` 钩子覆盖（含
   `x<0` 判定）。

   为找内联副本做过的检索都失败，一并留档：(a) 精确签名 `0x2710` + `0xb504f333` +
   `0x16a09e666` 三件套，全库仅 1 处（真函数本身），无内联副本；(b) 按 `SafeSqrt` 的
   6 个调用点逐个反汇编，无一是 `p*100000` 形态；(c) 用 80 字节窗口搜出的 3 个疑似内联点
   经读体确认是 `x*x` 乘法辅助函数（假阳性）。

Linux 的 19 个 hook 目标在 Windows 侧全部覆盖。`cfx_get_rounded64` 因 COMDAT 折叠与
`cfx_get_rounded` 同地址；`cfx_safe_sqrt_int` 在 Windows 侧无对应代码。

#### 发现并关闭了一个真实的验证缺口

此前「`REPLACE=1` 跑过 350 万次调用不崩」只证明了不崩，没证明真改对了值：影子模式下
detour 照样返回 game 值，两者在日志上长得一样。

新增探针：传 `INT64_MAX` 给 `GetRounded`，看返回值是 game 的 wrap 值还是我们的饱和值。
`GetRounded` 是纯读函数（只读 `*param_1`、结果放返回值，不写回入参），所以判据看返回值。
第一版探针错看成输出槽，已修正。

A/B 实测（同一构建脚本，只差 `-Replace` 开关）：

| 构建 | `GetRounded(INT64_MAX)` 返回 | 含义 |
|---|---|---|
| `REPLACE=0` | `-92233720368547` | game 的 wrap 值（就是那个 bug） |
| `REPLACE=1` | `+92233720368547` | **饱和值（被纠正了）** |

这是端到端证明：回写路径确实把一个溢出值纠正了。

#### 策略分布与 Linux 对齐

> ⚠️ 下面这张表是 **0.1 那一轮**的快照（当时 17 个目标），**已经不是当前状态**。
> 当前策略分布见 0.1 开头：**EXACT 8 / INPUT_GUARD 1 / OBSERVE 9**。
> 两处变化：三个上限函数从 OBSERVE 升到 EXACT（0.1.12）、新增 `damage_per_day`（EXACT，0.1.14）；
> 而 `var_add` / `var_multiply` 从 EXACT **降回** OBSERVE（0.1.4 的更正）。
> 本表保留原样存档。

| | EXACT | INPUT_GUARD | OBSERVE |
|---|---|---|---|
| Linux | 6 | 2 | 11 处钩子（含 `cfx_get_rounded64`） |
| Windows | 6 | 1（`Sqrt`） | 10 |

EXACT 集合完全相同（`cfx_get_rounded`、`cfx_to_fp15`、`apply_mul_cfx`、
`apply_mul_fp15`、`var_add`、`var_multiply`），也就是能真正修数值的那部分能力已对等。
`cfx_get_rounded64` 因 COMDAT 折叠与 `cfx_get_rounded` 同一地址，一个钩子覆盖两者。
唯一的真缺口是 `cfx_safe_sqrt_int`（INPUT_GUARD 少 1 个），见上。

### 0.1.12 三个上限函数升级成忠实重算（EXACT）

旧 `detour_max_hp` 只做阈值检查（`if (v < 0 || v > cap)`），既不重算也不回写，所以
「溢出后变成 0 / 负数」修不了。新实现用游戏自己的原语重算并等值比对，常量全部**读 Windows
函数体得出**（不是照抄 Linux）：design 偏移 hull `0x10` / shield `0x130` / armor `0x70`；
加算/乘算 ModifierType hull `0x1e`/`0x1f`、shield `0x2e`/`0x2f`、armor `0x24`/`0x25`；
条件性船级修正 shield `0x1c8`/`0x1c9`、armor `0x1c6`/`0x1c7`（船体未建模）。
完整表格与实机逐位一致的四例见 0.0 变化 1。

**踩过的两个坑**：

1. **漏掉按舰船等级的额外乘算修正表**。`bVar1 = *(byte*)(design + 0x468)`，表地址 shield
   `0x28167ac` / armor `0x2816774` / hull `0x281673c`。漏掉它重算会**系统性偏小** ——
   实测 游戏 = 21304430712 而重算 = 1782290712（差 13 倍）。这一段在游戏里是内联展开的，
   结尾不做 `modifier_value` 内部那一项相加，所以不能复用辅助函数，必须自己扫表。
2. **误以为「三个上限函数返回的全是 0」**。那是我们自己的 `detour_max_hp` **读错了返回位置**，
   不是游戏返回 0。实机日志证明它们返回真实值（`75000000` / `6023399996` 等）。这与 0.3
   记的两次 ABI 踩坑是同一类错误的第三次 —— 又一次是「参数/返回槽角色搞错，探针或日志先打脸」。

### 0.1.13 「护盾塌成 0」的根因（三步）与封顶判据

根因与实测证据见 0.0 变化 2。要点复述：加算真值超过 `INT64_MAX/1e5` → 游戏 mul wrap 成负 →
`GetModifierValue` 的 `if (v < 0) v = 0` 兜底把整项夹成 0 → 上限 = `(base+0) × 倍率` = 0。

封顶判据是「加算读到 0 + 倍率 ≥ 1e7 倍 → 封顶到 `INT64_MAX`」。**这条判据只对值住在加算项的
目标（护盾/装甲）生效**，船体的加算项正常就是 0，用同一条会误伤，已用 `add_carries_value`
标志按目标分别开关。实机：只有 `CalcMaxShieldHitPoints` 触发，船体/装甲零误报。

### 0.1.14 新增第 18 个目标 `damage_per_day`

定位踩坑与三条「只影响显示」的证据见 0.0 变化 3。一句话总结判据：伤害 = 总计 × 倍率，
**不可能为负**，负值或 > 9.2e13 游戏单位必然是 wrap；`*r` 是 sret 返回槽，写它不会碰到别的统计项。

### 0.1.15 性能修复（用户反馈「过一天变慢」）

两处开销与快/慢路径实测数字见 0.0 变化 4。补一条纪律：`fast_read` **只用于地址来自游戏
自己传入指针**的场合；任何来自我们解析的 RVA / 猜测的偏移，仍然必须走 `safe_read`。

### 0.1.1 `apply_mul_cfx` 的身份：四重交叉验证

函数体指纹分不出来（75/65 个同形状候选），所以换成靠调用者定位：

1. Linux 侧有 78 个函数调用 `ApplyModifierMult`，其中 35 个带字符串字面量；
2. 取 `CalcStarbaseCapacity`（其 `STARBASE_CAPACITY_MAX_REACHED` 唯一命中 Windows dump 的 `FUN_14073c540`），发现它两次调用 `FUN_14036df80`；
3. `FUN_14036df80` 体内正是 `*(DAT_142814390 + 0xa0 + type*0xb0)` 的类型表查找 + `(v*m)/100000` + 拆分回退，与 Linux 962696 逐行对应；
4. 交叉验证：把 `FUN_14036df80` 的 41 个调用者按字符串认出 Linux 同名函数后，函数名与调用次数同时吻合：

   | Windows 调用者 | 识别依据（字符串） | 次数 | Linux 对应 | Linux 次数 |
   |---|---|---|---|---|
   | `FUN_14073c540` | `STARBASE_CAPACITY_BASE`… | 2 | `CalcStarbaseCapacity` | 2 ✓ |
   | `FUN_14072e570` | `HOSTILE_CLAIMS_PROTECTION`… | 2 | `CalcClaimInfluenceCost` | 2 ✓ |
   | `FUN_140a42ca0` | `FEDERATION_ENVOYS`… | 1 | `BuildEnvoysTooltip` | 1 ✓ |
   | `FUN_14071fc60` | `EMPIRE_SIZE_FROM_DISTRICTS`… | 6 | `CalcEmpireSize` | 8 |

   四个独立调用者在名字与调用次数两维同时对上，这是证明，不是推测。

`apply_mul_fp15`（`0x36E0A0`）与前者地址相邻，把 fp15 换算内联了，所以按调用
`FUN_141b4c0a0` 搜是空的，我一开始就搜空了。公式
`((x%1e5)*0x40000000/0xc3500000 + (x/1e5)*0x8000) * *param_2 >> 0xf` 与 Linux 962872 一致。

两者都能做成真正的 EXACT。它们返回实际生效的倍率，所以影子复算不需要重新实现
`CModifier` 的类型表查找：`v0` 读入参、`m_eff` 取返回值、`cfx::mul(v0, m_eff)` 算精确值
再比对即可。这条路绕开了逆清 `CModifier` 内部结构这个难题。

### 0.2 EXACT 检出链的真机证据（读档不是必要条件）

`cfx_get_rounded` 的判定平时只有读档进局才会被走到，但它是纯函数（读一个 int64、返回一个
int64、不碰游戏状态），所以插件在 `SATFIX_WIN_FORCE=1` 时用极值直接把真函数调一遍，
也就是活体探针。链路是 `detour → 蹦床 → 真实的游戏函数 → 判定 → EVENT`：

```
探针 GetRounded in=123456              -> game=1
探针 GetRounded in=9223372036854725807 -> game=92233720368547     ← 上界最后一个安全值
EVENT GetRounded x=9223372036854725808 game=-92233720368547 sat=92233720368547
探针 GetRounded in=9223372036854725808 -> game=-92233720368547    ← 第一个坏值
EVENT GetRounded x=9223372036854775807 game=-92233720368547 sat=92233720368547
探针 GetRounded in=-9223372036854775808 game=92233720368547 sat=-92233720368547
```

同时证明了三件事：游戏真的会算错（用的是它的机器码，不是我自己的模型）、蹦床链没坏、
判定与饱和值正确。

### 0.3 两次 ABI 踩坑

1. 同形状不等于同 ABI。`0x75A370` 与 `0x1B4C0A0` 函数体公式完全一样，但调用点
   （`FUN_14075a370(&local_res20, 1000)`，第二个参数是缩放标量）说明前者是带缩放参数的
   另一种换算，不是 `operator fpml<...,15>`。我最早把 `0x75A370` 当目标，活体探针四个输入
   返回同一个常数 `1767657313`，因为我的 `&x` 被当成了缩放值。
2. 机器码要看参数顺序，不能只看寄存器角色。即使把 `0x1B4C0A0` 认对了，我还是把
   `(ret, src)` 写成了 `(src, ret)`，探针就恒返回 0（它读 `*(&slot)`=0 当源）。直到解码
   前 6 字节（`4c 8b 01`=`mov r8,[rcx]`、`4c 8b d2`=`mov r10,rdx`）才定下 `rcx=源, rdx=返回槽`，
   即 C++ 参数顺序是 `(src, ret)`。

两次都是活体探针先打脸、再修好的。没有它，第 1 个错误要等到开 REPLACE 才会以写坏内存的
形式暴露。

### 0.5 `REPLACE=1` 回写路径的实机证据

用 `.\build.ps1 -Replace` 重新编译后再跑同一组探针，对比影子/回写两种模式：

| 输入 | 影子模式（游戏值） | REPLACE 模式 | 说明 |
|---|---|---|---|
| `123456` | `1` | `1` | 不越界 → **不改**（只有真分歧才回写） |
| `INT64_MAX` | `-92233720368547`（buggy） | **`92233720368547`** | 回写成正确值 |
| `9223372036854725808` | `-92233720368547` | **`92233720368547`** | 上界第一个坏值 |
| `INT64_MIN` | `+92233720368547` | **`-92233720368547`** | 下界 |

这条证据说明回写逻辑的两个要害都对了：只在真分歧时动手，而且写进去的是正确的饱和值，
而不是把游戏值原样写回。

不带参数跑 `build.ps1` 编出来的仍然是影子模式，回写要显式开。

### 0.6 还没做完的部分

本节是 0.1 之前的遗留清单，留在这里存档。0.1/0.1.1 到 0.1.15 里已经解决的项没有从下面删掉，
以那几节为准。下面每条后面括注了**当前的结论**，方便对照。

* **`apply_mul_cfx` / `apply_mul_fp15` 身份未证实**（**已解决**，0.1.1：靠调用者法定为
  `0x36DF80` / `0x36E0A0`，候选 `0x3E6AA0` 是错的）。首选候选是
  `FUN_1403e6aa0 @ 0x3E6AA0`：80 行、82 个调用点（Linux 版 81 行），体内有裸乘
  `(v*m)/100000` + `0xb504f333/0x16a09e667` 双输入安全域 + 拆分回退，与 Linux 版同源。
  但不敢装：这个 dump 里有 75 个函数含同一套 CModifier 惯用法（含大量内联副本），
  常量指纹无法唯一区分；而且它会就地改写状态（对 `param_1+0x38` 的 0x10 步长数组累加），
  不能用活体探针那种不改状态就能验证 ABI 的办法。要确证它得去 Ghidra 里看调用点的类型。
* **`cfx_sqrt` / `cfx_safe_sqrt*` 未定位**（**已解决**，0.1.6：靠调用者法定为 `0x1B489D0` /
  `0x1B4C600`；`cfx_safe_sqrt_int` 经 0.1.11 判定 Windows 侧**不存在**，非缺口）。
  `0xb504f334` 经查不是 Sqrt 独有常量（它出现在
  若干 CModifier 惯用法里，原先的推断是错的），目前没有可靠指纹，需要专门做。
* **`var_add` 未定位**（**已解决**，0.1.2：`0x177800`，靠 4 个 helper 的调用组合定位）。
  已确证的 `var_multiply` 在 RVA `0x1777F00`（**注意：不是 `0x231640`**，那个是错的，见 0.1.3），
  但它周围 0x230500–0x231800 全是无关小函数，`CAddVariableEffect` 不在这里；Linux dump 里也没有该
  符号（149 个 ExecuteActual 里无法用常量区分加法/乘法版本）。
* **4 个 helper 暂不做**（**已做**，现在是 6 个 helper、签名校验 `6/6`）：
  `AccessVariablePointer` `0x9F7DF0` / `cvars_get` `0x227390` / `cvars_set` `0x7AAE10` /
  `cfp_getvalue` `0x34D500`（变量系统用），外加上限重算链的
  `ship_size_of` `0x30E990` / `modifier_value` `0xD29DD0`。
  注意：变量系统那两个 helper 虽然打通了读回链，但 `var_add`/`var_multiply` **仍是 OBSERVE**
  （见 0.1.4 的更正），所以它们目前是「已解析、未用于回写」。
* **`mpe15`/`mpe7`/`diplo_weight`/`shield_max`/`armor_max`/`hull_max`**：全 OBSERVE
  （**已解决定位**，0.1.2 / 0.1.8 / 0.1.10）。其中三个上限函数**已升级为 EXACT**（0.1.12）；
  `mpe15`/`mpe7`/`diplo_weight` 仍是 OBSERVE。
* **正常游玩几乎不会产生 EVENT**：原版量级离阈值极远（`GetRounded` 要 `x > 9.2e17`），
  所以正常游玩时 0 条 EVENT 应读作预期结果。要验证检出链请用活体探针（第 4 节）。
  （这一轮不一样：`CalcMaxShieldHitPoints` 与 `CalcAverageDamagePerDay` 在用户的极端存档上
  抓到了真实 EVENT，见 0.0。）
* `REPLACE=1` 只编译过，回写路径尚未实机跑过（**已解决**，0.5 + 0.1.11 的 A/B 证明）。

---

## 1. Windows 侧为什么不能照抄 Linux 的定位方式

Linux 版靠符号名定位：

```
nm stellaris → mangled 名 → 地址 → 运行时 dlsym / 读 /proc/self/exe 的符号表
```

Windows 的 `stellaris.exe` 实测（`pefile`）：

| 项 | 值 | 后果 |
| --- | --- | --- |
| 导入表导出的符号 | 110 个 | `GetProcAddress` 拿不到任何游戏函数 |
| C++ 符号 | 无 | 没有 mangled 名可用 |
| PDB | 无（游戏目录里只有 `dbghelp.dll`） | 不能从符号服务器拿 |
| `.pdata` | 134803 个函数 | 只有地址区间，没有名字 |
| RTTI | 1269 条类名 | 只能给类，给不了非虚成员的地址 |

所以改成硬编码 RVA + 序言字节签名双重校验。RVA 由静态分析确证（见第 3 节）；运行时先按
RVA 读前 16 字节，与签名逐字节比对；不匹配（游戏更新过，或注入到了别的程序）就跳过该
目标并写日志，绝不盲目读写内存（手册 6.4、7 节的要求）。

`tools/gen_targets_win.py --check` 把这份校验提前到构建期。

### 1.1 映射里的函数名不是身份证明

`_analysis/win_linux_mapping_final_452.json` 里有 10186 对 `FUN_ → Linux 名`，看着很诱人，
但它是字符串字面量指纹匹配出来的。`confidence: "exact"` 的意思只是这个字符串指纹唯一
命中，不代表这个函数就是同名的 Linux 函数。

实测的两个反例，直接读函数体就能看出来：

| 映射说 | 实际是 |
| --- | --- |
| `FUN_1408b3700` = `ApplyModifierMult` | modifier token 分发器（把 `param_3` 与 `0x2a7b/0xb5/0x31a` 比较） |
| `FUN_1408b3e00` = `ApplyModifierMult` | 析构函数（写回 vtable、释放内存） |

所以本表只采信函数体形状，逐条证据写在目标表的 `evidence` 字段里。

---

## 2. 架构

### 2.1 `winhook.hpp` — hook 引擎

算法与 `hooklib/shk.hpp` 逐条保留，只换 OS 那一层：

| Linux (shk) | Windows (whk) |
| --- | --- |
| `/proc/self/exe` + ELF `.symtab` | 没有符号，改用 RVA 表 + 序言签名 |
| `mprotect(RWX)` | `VirtualProtect`（并保存/恢复原保护） |
| `mmap(MAP_FIXED_NOREPLACE)` | `VirtualQuery` 找空洞 + `VirtualAlloc` |
| `munmap` | `VirtualFree` |
| `__builtin___clear_cache` | `FlushInstructionCache` |
| （无） | `SuspendThread` 其余线程，让 5 字节补丁原子化 |

解码器可以直接照搬：指令长度编码由 x86-64 架构决定，与操作系统无关。shk 对真实
`stellaris` 的 139452 个函数做过前 12 字节必须能完整解码的全量扫描，失败 0 个。
Windows 上真正的差异在函数序言形状（MSVC vs GCC），所以 whk 不假定一致，而是用序言签名
在安装前显式检查。

补掉的两个 shk 缺陷：

* `mark_hooked` / `unmark_hooked` 原来各自声明函数局部 `static`，两张表互不相通；而且
  `unmark` 是空操作，安装失败也会把地址永久占住。现在共用一个 `HookRegistry` 单例，
  `remove()` 真的删（尾部元素填补空洞），所以失败后重试和卸载后重装都能用，自测第 7 节
  专门验证这条。
* MSVC 禁止在需要对象展开的函数里用 `__try`（C2712），而 `InlineHook` 有 `std::vector`
  成员，所以 SEH 的 `memcpy` 被抽成独立的 `seh_memcpy`。

### 2.2 `satfix128.hpp` — 128 位中间量

饱和判定必须在 128 位上做，游戏溢出正是因为中间乘积只用 64 位。

不用 `std::_Signed128`：它虽然实测可用，但那是 MSVC 的未文档化内部头，随工具链更新
可能改形状。这里只依赖 `<intrin.h>` 里四个有文档的内建：`_umul128` / `_mul128` / `_udiv128`
（外加自己写的长除）。

关键点：`_udiv128(hi, lo, d, &r)` 在 `hi >= d` 时会触发 #DE（除零错），而我们的商经常超过
64 位（例如 `2^126 / 100000`），所以 `udiv128by64` 自己长除，先算商的高 64 位，把余数接到
低位再除一次，保证每次调用 `_udiv128` 时其 high 参数都严格小于 d。

`mul_shift_sat` 里 `a * b` 可能超过 2^127，所以先取幅值、算术右移之后再取负，避免把中间值
搬进有符号 128 位。

### 2.3 线程模型（手册 6.3，最容易让游戏静默崩的地方）

被 hook 的函数本身运行在游戏主线程，所以 detour 里读参数、算影子、写回值是安全的。
detour 只做纯算术加原子计数，重活（日志格式化、配置重读、统计汇总）排到 `g_tasks`，由
主线程泵在下一次游戏主线程进入任一被 hook 函数时执行。

这样既不必 hook `Present`/DXGI，也不会从别的线程碰引擎状态。

自己那个线程只做等待与 `GetFileAttributesExW`（手册 6.3 允许的事），在 `DllMain` 里创建
（手册 6.1：`DllMain` 只 `CreateThread`，不等待/不加载库/不做 IO）。

---

## 3. 已确证的目标清单（按片区）

**当前共 18 个目标**（EXACT 8 / INPUT_GUARD 1 / OBSERVE 9）+ 6 个辅助函数，未定位 1 个；
完整清单与策略见第 0 节与 `src/satfix_targets_win.generated.hpp`。
本节按片区展开**定位证据**，逐个列的是 CFixedPoint 族与变量系统那几个（它们的证据最完整、
踩坑最多）；`shield_max`/`armor_max`/`hull_max` 与 `damage_per_day` 的证据见 0.0 与 0.1.12 ~ 0.1.15。

比对基准是 Linux 反编译 `stellaris_4.5.2_source.cpp`；两侧 build hash 逐字节相同
（`32709cf254181b032b1b309a6ea09776`）。复核命令：

```powershell
python tools\win_dump_index.py --dump ..\..\_analysis\stellaris_4.5.2_win_symbolized.cpp `
    --index ..\..\_analysis\win_dump_index.jsonl --fun FUN_141b4c170 --body
```

### 3.0 一条定位捷径：CFixedPoint 的成员成簇排布

`0x1B4C0A0`–`0x1B4C600` 这段密集排着 CFixedPoint 的成员函数（同一 COMDAT 组）：

```
0x1B4C0A0  operator fpml<...,15>() const      -> cfx_to_fp15
0x1B4C100  GetRounded(fpml<...,15> const&)    -> cfx_get_rounded_fp15
0x1B4C170  GetRounded()/GetRounded64()        -> cfx_get_rounded
0x1B4C1B0  RoundTo(CFixedPoint const&)        -> cfx_round_to
0x1B4C2D0  Atan2(CFixedPoint const&, ...)     -> cfx_atan2
0x1B4C600  （缩放+循环，Sqrt 族候选，未确证）
0x1B4C840+ std::string 解析（0xf SSO 判定）等无关函数，排除得很干净
```

`GetRounded` 与 `GetRounded64` 的 Linux 函数体完全相同，MSVC 的 COMDAT 折叠把它们合并成
了一份，所以只有一个地址。这也解释了为什么按名字查 `GetRounded` 得 0 命中、按形状查只有
1 个孪生。

### 3.1 `cfx_get_rounded` — RVA `0x01B4C170`（EXACT）

Windows（`FUN_141b4c170`，17 行）：

```c
lVar1 = *param_1;
lVar2 = lVar1 + -50000;
if (-1 < lVar1) { lVar2 = lVar1 + 50000; }
return lVar2 / 100000;
```

Linux（`CFixedPoint::GetRounded` 反编译 8599412 / `GetRounded64` 8599430，
两个函数体完全相同）：

```c
lVar1 = *(long *)this;
if (-1 < lVar1) return (lVar1 + 50000U) / 100000;
return -((50000U - lVar1) / 100000);
```

逐字一致。MSVC 的 COMDAT 折叠把这两个相同函数合并成了一份，所以只有一个地址，这与
脚本里查 `GetRounded` 得 0 命中、`GetRounded` 形状的孪生只有 1 个互相印证。

这是唯一一个已实测确认会溢出的目标，不依赖任何 mod 数值假设。`x + 50000` 与
`50000 - x` 各在一端溢出，实测：

```
INT64_MAX: 游戏 = -92233720368547   饱和 = +92233720368547
INT64_MIN: 游戏 = +92233720368547   饱和 = -92233720368547
```

### 3.2 `cfx_to_fp15` — RVA `0x01B4C0A0`（EXACT）

Windows（`FUN_141b4c0a0`，10 行）：

```c
*param_2 = ((*param_1 % 100000) * 0x40000000) / 0xc3500000 + (*param_1 / 100000) * 0x8000;
```

Linux（`CFixedPoint::operator_cast_to_fixed_point` 反编译 8599274，即
`operator fpml::fixed_point<long long,48,15>()`）：

```c
*(long *)this = ((*param_1 % 100000) * 0x40000000) / 0xc3500000 + (*param_1 / 100000) * 0x8000;
```

公式逐字节相同。ABI 由机器码加调用点确证，这是两次踩坑换来的：机器码前 6 字节里
`4c 8b 01` = `mov r8,[rcx]`（源从 rcx 进来且解引用）、`4c 8b d2` = `mov r10,rdx`
（返回槽是 rdx）；调用点是 `FUN_141b4c0a0(&DAT_1431517c8, local_368)`，第一个实参是源、
第二个是结果变量。

所以 C++ 参数顺序是 `(src, ret)`。实机探针（4 个输入）返回值
`40454 / 3022314549036572936 / -3022314549036572936 / 0` 与模型逐位吻合，0 分歧，
这与 Linux 侧认为该换算溢出不了的结论也一致。

> 曾经找错目标：`FUN_14075a370` 的函数体公式和这个完全一样，但它的调用点全是
> `FUN_14075a370(&local_res20, 1000)` 这种第二个参数为缩放标量的形式
> （1000/10000/100000/1000000），所以它是另一个带缩放参数的换算。我最早把 `0x75A370`
> 当目标，活体探针四个输入返回同一个常数 `1767657313`，因为我的 `&x` 被当成了缩放值。

### 3.3 `cfx_round_to` — RVA `0x01B4C1B0`（OBSERVE）

Windows（`FUN_141b4c1b0`，31 行）与 Linux `CFixedPoint::RoundTo`（反编译 8599448）同构：
先按 `lVar3 + 0x53e2d6238da3U < 0xa7c5ac471b47` 判量级，小量级走 `(x*100000)/200000`、
大量级走 `(lVar2%200000)*100000/200000 + (x%100000)*100000/200000` 的拆分路径，结尾：

```c
*param_1 = lVar3 - lVar3 % lVar2;
return lVar3 / lVar2;
```

与 Linux 版的 `*(ulong *)this = uVar3 - (long)uVar3 % (long)uVar4; return (long)uVar3 / (long)uVar4;`
逐字对应。ABI 是非 sret（返回值在 rax）；rcx = this（会被就地改写），rdx = 除数。

实机探针：`self=1234567, div=1000 → self'=1235000, q=1235`；`div=200000 → 1200000, q=6`
（手算 `1234567+500=1235067`，`1235067/1000=1235` 余 67；`1235067/200000=6` 余 35067，
`1235067-35067=1200000`），完全吻合。

列为 OBSERVE 是因为 Linux 侧同样只观测（记 `divisor==0` 与 `v+divisor/2` 溢出）。
本移植的 detour 也顺带检查 `divisor == 0`，那会让游戏直接 #DE 崩掉。

### 3.4 `cfx_atan2` — RVA `0x01B4C2D0`（OBSERVE）

Windows（`FUN_141b4c2d0`，98 行，Linux Atan2 也是这个量级）同时命中 Atan2 的五个标志常量：

| 常量 | 含义 |
|---|---|
| `0x132cb` | `π/4 × 1e5` = 78539（Linux 版 `(long)(uVar8 * 0x132cb) / 100000`） |
| `0x39863` | `π × 1e5` = 235619（Linux 版 `lVar5 = 0x39863`） |
| `0x53e2d6238da3` | 与 RoundTo/Sqrt 共用的量级安全界 |
| `0xb504f333` / `0x16a09e667` | 中间积不撑爆 int64 的安全域 |

五个同时出现，是这一族里最强的一次指纹命中。ABI 是 sret(rcx=返回槽) 加两个 CFixedPoint
指针(rdx, r8)。实机探针 `(1.0,1.0) → 78539`（正是 π/4×1e5）、`(1.0,0) → 157078`
（≈π/2×1e5），返回值与数学期望逐位吻合，身份与 ABI 都对。

列为 OBSERVE 是因为 Linux 侧同样只观测（记参数平方会溢出的量级），而 Atan2 是多项式逼近，
重写逐位等价参考实现成本高且容易错（Linux README 第 5 节）。

### 3.5 `cfx_get_rounded_fp15` — RVA `0x01B4C100`（OBSERVE）

Windows（`FUN_141b4c100`，23 行）与 Linux `CFixedPoint::GetRounded(fpml<...,15> const&)`
（反编译 8599289）结构同构，四个特征常量 `0x8000` / `0xf` / `0xc3500000` / `0x4000`
与 Linux 版逐一对上。ABI 是非 sret，参数是被转换的 fp15 位模式，不是 CFixedPoint。

Linux 侧同列 OBSERVE，本移植也只计数、不判罚。

### 3.6 `var_multiply` — RVA `0x01777F00`（OBSERVE）

> **RVA 已更正**：本节标题原先写 `0x00231640`，那个地址**装错了函数**，已被 0.1.3 推翻。
> 正确地址是 `0x01777F00`（由 Linux 侧那条独占诊断串
> `multiply_variable: variable %s is not set for scoped %s '%s' at %s` 唯一命中）。
> 策略**当前是 OBSERVE**（见 0.1.4 的更正说明），不是 EXACT。
> 下面保留原样存档的是**当时观测到的现象**，对象是那个错误的 `FUN_140231640`。

Windows（`FUN_140231640`，**旧地址、已证伪**，保留存档）：

```c
if ((lVar2 + 0xb504f333U < 0x16a09e667) && (param_3 + 0xb504f333U < 0x16a09e667)) {
    *plVar7 = *plVar7 + (lVar2 * param_3) / 100000;
    return;
}
...
*plVar7 = *plVar7 + ((lVar5 % 100000) * param_3) / 100000 + (lVar5 / 100000) * param_3;
```

`0xb504f333 = 3037000499`、`0x16a09e667 = 6068000998 = 2*3037000499+1`，正是中间积不撑爆
int64 的界，与 Linux `CModifier::ApplyModifierMult` 同源。

当时列为 OBSERVE 的理由是累加目标是 `CModifier` 内部 `0x10` 步长的条目数组
（`*(longlong*)((longlong)(int)uVar6 * 0x10 + *(longlong*)(param_1 + 0x38))`），语义未逆清，
无法精确复算写回值，所以只记被调用过。

> 顺带一提：**真正的** CModifier 放大出口是 `apply_mul_cfx` = `0x36DF80`（已确证、EXACT），
> 那条路已单独确证，与变量系统无关。

---

## 4. 编译 / 运行

需要 VS 2022 Build Tools（x64 C++ 工作负载 + Windows SDK）。本机是
MSVC 14.44.35207 + Windows SDK 10.0.26100.0。

```powershell
.\build.ps1              # 影子模式：跑全部自测 + 编译 + 组包 + 包合规检查
.\build.ps1 -Replace     # 打开溢出回写
.\build.ps1 -TestOnly    # 只跑 hook 引擎自测
```

`build.ps1` 会依次跑三套自测，任何一套失败都中止：

```
test_winhook.exe       25/25   hook 引擎（合成机器码，不开游戏）
test_stl_fix_win.exe   58/58   定点饱和算术对拍 + 判定逻辑自检向量表
test_load_plugin.exe   23/23   插件管线（宿主 LoadLibrary）
check_plugin_pkg.py    23/23   插件包合规（手册第 13 节）
```

安装与启动：

```powershell
$stl = "$env:LOCALAPPDATA\Programs\Stellaris Launcher\stl.exe"
& $stl plugin install .\plugin --link    # 开发时用链接
& $stl plugin enable satfix
& $stl launch
Get-Content .\plugin\logs\satfix.log     # ← 看这里
```

也可以手动注入已在运行的游戏：`& $stl inject .\plugin\satfix.dll`。

### 活体探针（验证 EXACT 检出链，不需要读档）

```powershell
$env:SATFIX_WIN_FORCE = '1'          # 触发活体探针
& $stl launch                        # 或先开游戏再 stl inject
# 日志里会出现「探针 GetRounded in=… -> game=…」与对应的 EVENT
```

`SATFIX_WIN_FORCE=1` 同时会绕过必须是 `stellaris.exe` 的检查（给离线自测用），正常游玩
不要设它。探针只调两个纯函数、不改任何东西，全程有 SEH 包住。

### 游戏更新后

```powershell
python tools\gen_targets_win.py --check   # 签名/时间戳漂移 -> 非 0 退出
```

漂移了就要重新确证 RVA（流程见第 5 节），然后 `tools\gen_targets_win.py` 重新生成，
并把新的 `exe_timestamps` 加进 `plugin\stl-plugin.json`。

---

## 5. 怎么继续补剩下的目标

已经在 Windows dump 里建好了索引与指纹工具，补一个目标大约四步：

```powershell
# 1) 从 Linux dump 取参考函数体，看清它的「形状」
#    （CFixedPoint 成员先从 0x1B4C0A0 附近的簇里找，最快）
python tools\win_dump_index.py --dump ..\..\_analysis\stellaris_4.5.2_win_symbolized.cpp `
    --index ..\..\_analysis\win_dump_index.jsonl --rva 0x1b4c600 --body

# 2) 在 Windows 侧按常量指纹筛候选
python tools\win_fingerprint.py --dump ..\..\_analysis\stellaris_4.5.2_win_symbolized.cpp `
    --index ..\..\_analysis\win_dump_index.jsonl --report --tag cfx_to_fp15

# 3) 【关键】ABI 不能靠函数体猜，要看两处：
#    a. 函数头（dump 里的签名，参数个数/类型）
#    b. 调用点（`FUN_xxx(` 在本 dump 里的形态）—— 决定寄存器里到底是什么
#    两者的教训见 0.3/0.4：0x75A370 vs 0x1B4C0A0 函数体一样、ABI 不同。

# 4) 把 (key, 描述, RVA, 策略, 证据) 加进 tools\gen_targets_win.py 的 CONFIRMED
#    -> python tools\gen_targets_win.py 重新生成头文件
#    -> 在 src\sat_guard_win.cpp 里补 detour（纯函数再加活体探针）
#    -> pwsh -NoProfile -File run_inject_test.ps1   # 实机验证
```

加探针是这套流程里最划算的一步。只要目标接近纯函数，探针就能在几秒内于真进程里把 ABI
与身份同时证伪或证实，比读档快得多，0.3 的两个坑都是它抓到的。

现成的指纹工具（`win_fingerprint.py`）已经能给出分类候选，当前的命中数：

| 标签 | 函数数 | 说明 |
| --- | ---: | --- |
| `cfx_split_mul` | 772 | `(X%1e5)*Y/1e5 + (X/1e5)*Y` 的拆分乘法形状 |
| `fpml7_shift` | 359 | `>>7` 方言 |
| `fpml15_shift` | 263 | `>>15` 方言 |
| `cfx_get_rounded` | 140 | `+50000` 且 `/100000` |
| `cfx_to_fp15` | 53 | `0x40000000` 且 `0xC3500000` |
| `cfx_round_maybe` | 82 | 四舍五入到 1e5 倍数 |

### 5.1 剩下的目标为什么不是「再花点时间」就能解决

> ⚠️ **本节是历史存档**：那时的「剩下的 16 个」后来**全部定位完了**（18/19，唯一未定位的
> `cfx_safe_sqrt_int` 已判定 Windows 侧不存在）。当时总结的三条判据 —— 类型恢复、BSim、
> 活体探针的局限 —— 如今被**更有效的三条**取代：NDefines 名字法（0.1.8、0.1.10）、
> **片区扫**（0.1.14，靠它救回了一次错误定位）、**ModifierType 序列逐个比对**（0.1.14）。
> 下面的证据表仍然有效，它记录的是「当时试过什么、为什么不够」。

我把剩下的 16 个都试过一轮指纹，结论是它们需要的不是更多常量匹配，而是类型恢复。证据：

| 尝试 | 结果 |
|---|---|
| 常量指纹（6/7 命中 CModifier 惯用法） | 75 个函数，无法区分 |
| 加锐（要求 `+0xa0`/`+0xa8` 与 `*0xb0` 同块的表查找组合） | 仍有 65 个 |
| `0xb504f334` 当 Sqrt 独有常量 | 证伪，它出现在若干 CModifier 惯用法里 |
| `win_linux_mapping` 里的 `ExecuteActual` | 133 条，全部只标 `ExecuteActual`，无法区分加法/乘法版本 |
| `win_linux_mapping` 里的 `GetVariable` / `AccessVariablePointer` | 0 命中 |
| `win_linux_mapping` 里的 `CalcMaxArmorHitPoints` | 1 条，但只给名字 |
| Ghidra 工程查类型 | 无 PDB ⇒ 工程里没有类型库，反编译器给不出 `CModifier*`，所以拿不到参数类型 |

`apply_mul_cfx` 的首选候选 `FUN_1403e6aa0 @ 0x3E6AA0`（80 行、82 个调用点）形状很像但
签名对不上：它是 `(a, b, c)`，第 3 个参数当乘数用；而 Linux 版
`ApplyModifierMult(CFixedPoint&, CModifier const&, ModifierType, bool)`
的第 3 个参数是**修正类型**（拿去 `*0xb0` 索引全局表）。所以它不是那个函数。

下一步该做的事，按性价比排：

1. 做类型恢复：给 `_analysis/stellaris-c452.rep` 打 `_analysis/_win_rtti_classes.json` 里那 1269 条 MSVC RTTI 名（建类型库把 `param_1` 推成 `CModifier*`），再按参数类型 == CModifier 筛候选。这一步能把 65 个候选直接压到个位数。
2. 或者用 BSim（需两侧二进制，Linux `stellaris` 与 Windows exe 都在手边），按函数语义相似度匹配，绕开常量指纹。
3. 确证一个之后，活体探针只能验纯函数。`ApplyModifierMult` 会就地改写 `param_1+0x38` 的 0x10 步长数组，所以要么先逆清那个数组，要么只在 `REPLACE=0` 下先跑影子（读参数 + 只计数）。

在类型恢复做完之前，不建议给这 16 个里的任何一个装钩子。装错目标在 `REPLACE=1` 下会写坏
存档，而 `REPLACE=0` 也只是多记几行没用的日志。

> 事后看，这条纪律救过场：`var_multiply` 一度被指到 `0x231640`（那是 CModifier 惯用法，
> 不是变量系统），`damage_per_day` 一度被指到 `FUN_1403c2910`（那是「单件武器」那层）。
> 两处都是「形状像但身份错」，两处都是靠更硬的判据（独占字符串 / ModifierType 序列）纠回来的。
> 这正是「宁可漏报，不可误改」在**定位**阶段的同一体现。

---

## 6. 已知限制

本节同样是 0.1 之前的快照。0.1.1 已经把 `apply_mul_cfx` / `apply_mul_fp15` 确证下来并装上；
注意「`var_multiply` 升级成 EXACT」这句**已过时**（当前是 OBSERVE，见 0.1.4 的更正），
而三个上限函数与 `damage_per_day` 现在是 EXACT。当前状态见第 0 节。下面保留原样存档。

- 覆盖 8/23 个目标（**当时**的数字；当前 **18/19**，见第 0 节）。其中 4 个 EXACT
  （`cfx_get_rounded`、`cfx_to_fp15`、`apply_mul_cfx`、`apply_mul_fp15`），4 个 OBSERVE。
  主战场 `ApplyModifierMult` 两个重载已拿下，且实机确认 `apply_mul_cfx` 被调用 144 万次/局。
- `apply_mul_cfx` / `apply_mul_fp15` 身份未证实，插件不装它们。首选候选 `FUN_1403e6aa0`
  形状像但签名对不上（第 3 个参数是乘数，而 Linux 版是修正类型），所以它不是。要往下走
  必须先做类型恢复，详见 5.1。这是刻意的安全失败，不是遗漏。
- `var_multiply` 只观测，不判溢出、不替换（原因见 3.3）。**这一条当前仍然成立**
  （它本来就是 OBSERVE），只是理由要换成 0.1.4 里写的那条：EXACT 依赖先读到 `v0`，
  而 Windows 上 `v0` 的读取路径尚未验证。
- 正常游玩几乎不会产生 EVENT。原版量级离阈值极远，所以实机 0 条 EVENT 读作预期结果。
  要验证检出链请用活体探针（第 4 节）。
- `REPLACE=1` 已实机验证（0.5），但它会真的改写游戏数值，所以默认关闭。要用先备份存档
  （Linux 版 README 第 7 节⑤ 同样要求），并且清楚它只影响被 hook 到的那几个函数、同段内联
  副本不受影响。
- Windows 与 Linux 的对象布局不同（MSVC vs GCC），所以不能用 Linux dump 的 `+0x48` 这类
  偏移去读写 Windows 进程内存（手册 6.4 明确禁止）。本移植没有依赖任何结构偏移，
  已装目标的 detour 只读参数本身。
- `CFixedPoint` 的 `operator+ - * /` 全是内联（Windows 反编译里 `/100000` 出现 7022 处），
  没有符号，hook 不到，只能抓关口。这是与 Linux 版同样的固有局限。
- 蹦床按拷贝完整指令实现，不处理指令跨函数/跨页的极端情况，遇到就拒绝安装。
- `FreeLibrary` 只出现在测试里。游戏里插件永不卸载（手册 6.6）。
- 手册建议用 `_wfsopen(..., _SH_DENYWR)`，实测在宿主 `LoadLibrary` 场景下
  `_wfopen_s`/`_SH_DENYWR` 会给出 EACCES，而 `_wsopen_s(..., _SH_DENYNO)` 才真的允许别人读。
  日志因此用后者，并由 `test_load_plugin` 的可读性断言守住。
- 活体探针在初始化线程上调用游戏函数。这不违反手册 6.3 的那条（那条针对引擎/UI/逻辑
  函数），因为这两个目标是纯函数、无全局副作用，而且只在 `SATFIX_WIN_FORCE=1` 时跑。
  但若将来给非纯函数加探针，必须改成走主线程泵。

### 6.1 本轮新增的已知限制

- **上限重算是「乐观建模」**：条件性船级修正（`0x1c8`/`0x1c9`、`0x1c6`/`0x1c7`）的游戏侧
  触发条件依赖 `CFleet` 虚表与一个尚未逆清的函数，所以无条件加上。写回闸门（只在游戏值本身
  呈 wrap 特征时才动手）挡住因此产生的误判 —— 漏项只会让重算**偏小**，偏小的一侧不会把正常值
  判成溢出。
- **船体的条件性船级修正未建模**（配方里填 0）。船体目前靠「`v < 0`」那条分支兜底。
- **封顶值只能是 `INT64_MAX`**：定点格式本身的天花板。「单组件上限 × N」在数学上做不到，
  超过就立刻再 wrap，所以 92 万亿游戏单位是物理天花板，不是保守选择。
- **`damage_per_day` 只影响面板显示**，不影响实际伤害（三条证据见 0.0 变化 3）。
- **性能**：热路径每局被调用百万到千万次，任何逐调用开销都会被放大成可见的卡顿。
  已修两处（早退 + `fast_read`），但以后再加诊断必须能一键关掉。

---

## 7. 与手册的对照

| 手册条款 | 本移植的做法 |
| --- | --- |
| 6.1 `DllMain` 极简 | 只 `DisableThreadLibraryCalls` + `CreateThread`（自测断言 <500ms 返回） |
| 6.2 从模块地址找插件目录 | `GetModuleHandleExW(...FROM_ADDRESS)`，`test_load_plugin` 验证日志落在 DLL 旁 |
| 6.3 引擎调用只在主线程 | detour 只做算术+计数；重活走主线程泵 |
| 6.4 读内存防崩溃 | `whk::safe_read`（`VirtualQuery` 预检 + SEH），坏指针纯透传 |
| 6.5 与其他插件共存 | detour 一律 `call()` 原函数；不恢复/覆盖他人钩子 |
| 6.6 不卸载自己 | 没有 `FreeLibraryAndExitThread` |
| 6.7 其他 | `/MT` 静态运行库；`imports: KERNEL32.dll` 唯一依赖；不弹控制台；x64 |
| 7 适配游戏版本 | 清单列 `exe_timestamps`，DLL 再自查 PE 时间戳 + 16 字节序言签名 |
| 8 设置文件 | 读 `config\satfix.ini`，缺失用内置默认值，每 2 秒看 mtime 热重载 |
| 9 日志与排错 | 写 `logs\satfix.log`，可被他人同时读，上限 500 行，首行记版本/路径/构建 |
| 13 发布前检查 | `tools/check_plugin_pkg.py`（清单字段、包内不含 `config\`/`logs\`、无编译中间产物） |

---

## 8. 与 Linux 版的语义对应

| Linux | Windows | 说明 |
| --- | --- | --- |
| `shk::TypedHook` | `whk::TypedHook` | 同形；少了按符号名安装的重载（Windows 没有符号） |
| `__int128` | `sf128::U128` | `_umul128`/`_udiv128` |
| `eirin::saturating_*` | `sf128::*_sat` | 语义相同 |
| `eirin::fixed_num<...,15>` | `mul_shift_sat(a,b,15)` | 只实现 satfix 用得到的部分 |
| `cfx::mul_game` | 同名 | 离线对拍用（复现游戏的 wrap 行为） |
| `cfx::round_to_int_sat` | 同名 | 已与游戏原式对拍，复现出那次溢出 |
| `SATFIX_REPLACE` | `-DSATFIX_REPLACE` | 同为编译期开关 |
| `SATFIX_FORCE=1` | `SATFIX_WIN_FORCE=1` | 离线自测绕过必须是 stellaris.exe 的检查 |
| `SATFIX_HEARTBEAT=N` | `heartbeat_every`（配置项） | |
| `test/run_abi_check.sh` | `test/test_winhook.cpp` 第 3、4 节 | 用合成机器码，不需要开游戏 |
