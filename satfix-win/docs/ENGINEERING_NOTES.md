# satfix-win 工程档案：定位方法、ABI/LTCG 踩坑与版本演进

本文档归档 `satfix-win` 开发过程中的关键逆向方法论、实机排障案例、已证伪思路以及 4.5.2 → 4.5.3 → 4.6.0 的版本迁移记录。当前插件架构、目标清单与日常用法请见 [`../README.md`](../README.md)。

---

## 1. Windows 目标定位方法论

Windows 版 `stellaris.exe` 无 PDB、无 C++ 导出符号（约 110 个导出全为 PhysicsFS/CRT 边角），但 Linux 版二进制完整保留近 14 万个函数符号。所有定位均以「**同版本 Linux 反编译指路 → Windows exe/dump 独立确证**」为基本原则。

### 1.1 五类有效判据（按区分度与实战效果排序）

1. **掩码字节比对**（版本更新首选）
   - 将旧版已确证函数的完整机器码取出，用 Capstone 把 `call`/`jmp` 的 `rel32` 位移和 RIP 相对寻址 `disp32` 置为通配符，扫描新版 `.text` 并用 PE `.pdata` 异常表验证起点与长度。
   - 4.5.2 → 4.5.3（小版本）：25 个目标中有 **23 个**字节级完全一致；
   - 4.5.3 → 4.6.0（大版本）：25 个目标中有 **11 个**一击命中。
2. **独占诊断 / 报错字符串**
   - `var_multiply`：独占串 `multiply_variable: variable %s is not set for scoped %s '%s' at %s` 全库唯一命中；
   - `ship_size_max_hp`（`CShipSize::PostReadInit`）：三条报错串（`upgrade size ... not found` / `use_ai_design_role_from` / `invalid component set`）全部唯一落入该函数；
   - `cfx_safe_sqrt_int` 证伪：通过 `Cannot square root a number that is negative at %s` 唯一命中 `MTTHModifyNumber`。
3. **ModifierType 枚举立即数对 / 有序序列**
   - `GetModifierValue` 的第 4 参数 `ModifierType` 在 x64 ABI 中固定走 `r9d`。
   - 三个上限函数：各自专有的加算/乘算枚举对（4.6.0 中 hull `0x20/0x21`、armor `0x26/0x27`、shield `0x30/0x31`）在全库 142,256 个 `.pdata` 函数中唯一同现；
   - `damage_per_day`：依次喂给 `GetModifierValue` 的 7 个枚举序列（4.5.x 为 `0x3a/0x40/0x168/0x41/0x1d2/0x1d3/0x230`，4.6.0 为 `0x3c/0x43/0x170/0x44/0x1df/0x1de/0x23f`）全库唯一 7/7 同序命中。
4. **调用者法 & Helper 调用组合**
   - `apply_mul_cfx`：Linux 中有 78 个调用者，通过 `STARBASE_CAPACITY_MAX_REACHED` 唯一命中 `CalcStarbaseCapacity`，顺藤摸瓜定位被其连续调用两次的 `ApplyModifierMult`，再用 4 个独立调用者（名字 + 调用次数两维）交叉证实；
   - `var_add`：提取已确证 `var_multiply` 调用的 4 个 helper，反查同调用集合的变量效果家族，再由无乘法安全界与纯加法指令区分加/减/模/除。
5. **NDefines 注册 Thunk 法**
   - 适用于无直接调用者、无独占字符串的冷门目标（`diplo_weight`、`mpe15`、`mpe7`）。
   - 原理：Paradox 的 `NDefines::<组>::<名>` 字符串以明文存于 `.rdata`，`.text` 中存在唯一引用它的 5 指令注册 thunk：
     ```asm
     mov rcx, rdx
     lea r9,  [全局地址]        ; 该 define 真正的存放地址
     lea rdx, ["<组名>"]
     lea r8,  ["<define 名>"]
     jmp <注册函数>
     ```
   - 经 RVA→文件偏移转换（注意 `.rdata` 的 raw/virtual 对齐差），4.5.2 一举提取 2369 条 `(名, 组, 全局地址)`：
     - `DIPLOMACY_WEIGHT_POP_BASE` + `DIPLOMACY_WEIGHT_POP_HAPPINESS` 同时被读的函数全库唯一 → `diplo_weight`；
     - `MILITARY_POWER_EXPONENT` 唯一读者把该值当指数传给幂函数 → 再由移位宽度 `<<7/>>7`（fp7）与紧邻的 `<<0xf/>>0xf`（fp15）区分 `mpe7` 与 `mpe15`。

### 1.2 已证伪的思路（避免重走）

| 思路 | 实测结果与失败原因 |
| --- | --- |
| 信任字符串指纹自动映射表 | `win_linux_mapping_final_452.json` 标注 `exact` 的 `FUN_1408b3700`/`0x8b3e00`（标为 `ApplyModifierMult`）实际是 token 分发器与析构函数 |
| 用 CModifier 惯用法常量筛 `apply_mul_cfx` | Windows dump 中 75 个函数含同一套 `(v*m)/100000` + `0xb504f333/0x16a09e667` 惯用法，加表查找约束后仍有 65 个候选；历史曾误将 `0x231640` 当成 `var_multiply`、将 `0x3E6AA0` 拟作 `apply_mul_cfx` |
| 用单个常量 `0xb50679d3` 全库搜 `damage_per_day` | 4.5.2 误中 851 行的 `FUN_1403c2910`（单件武器层），真正的总计层在 `NShipUtil` 片区；且 4.6.0 该常量已变为 `0xb504f333` |
| 跨编译器照搬立即数掩码 | Linux `mpe15`/`mpe7` 的 `0x7fffffff8000` / `0x7fffffff80` 在 Windows 出现 0 次（MSVC 改为 `sar` + 事后掩码） |
| 跨编译器照搬结构偏移 | 已知偏移差异：`+0xb8 → +0xc0`、`+0xe8 → +0xf0`、`+0x808 → +0x8b0`、`CShipSize +0x678 → +0x6b8` |
| 跨版本沿用 ModifierType 编号 | 4.6.0 将 ModifierType 枚举整体位移（如 hull `0x1e/0x1f → 0x20/0x21`），必须从新版 Linux dump 重读 |

---

## 2. 六次 ABI 与内存偏移踩坑复盘

核心结论：**函数体公式一致 ≠ ABI 一致；相邻兄弟成员 ≠ 参数顺序一致；token-偏移映射逐字相同 ≠ 对象基址相同。**

| # | 目标 | 现象 | 根因与教训 |
| --- | --- | --- | --- |
| 1 | `0x75A370` 误认作 `cfx_to_fp15` | 活体探针 4 个不同输入全返回常数 `1767657313` | 函数体公式与 `cfx_to_fp15` 完全一致，但调用点为 `fn(&out, 1000)`，`rdx` 是缩放标量而非指针 |
| 2 | `cfx_to_fp15` | 活体探针全返回 `0` | 参数反序：正确签名为 `(src=rcx, ret=rdx)`，误写成 `(ret, src)` |
| 3 | `cfx_safe_sqrt` | 探针恒返回预置哨兵 `0x5A5A5A5A5A5A5A5A` | 同类兄弟成员参数相反：`Sqrt(out=rcx, src=rdx)` vs `SafeSqrt(src=rcx, out=rdx)` |
| 4 | `mpe15` / `mpe7` | 代码审查调用点发现 | 跨平台参数相反：Linux 为 `(out, exp, base)`，Windows 为 `(out, base, exp)` |
| 5 | `cfx_get_rounded_fp15`（v0.4.1） | 活体探针返回垃圾常数 `679080784` 且写坏入参 | 实际为 sret 两参 `(out=rcx, src=rdx)`，v0.4.0 误写成单参只转发 `rcx`，首次写日志破坏 `rdx` |
| 6 | `CShipSize::max_hitpoints` 偏移（v0.3.1） | 活体探针读出全是 `0`/`1`（实际是个 bool 字段） | Windows `CShipSize` 存在 `+0x40` 多继承子对象偏移，`ReadMember` 的 `this` 经 adjustor thunk 偏移过；`PostReadInit` 收到完整对象基址，真偏移为 `0x678 + 0x40 = 0x6b8` |

**独立于 Linux 的偏移实证法（HULLMAP 探针）**：在 `hull_max` 中拿已确证的 `ship_size_of(design)` 与面板基础船体 `base_raw = *(design + 0x10)`，全量扫描该 `CShipSize` 对象 `0x00..0xe00` 区间内值等于 `base_raw` 的槽位，仅命中唯一偏移 `0x6b8`。

---

## 3. LTCG 寄存器保全契约与 CTD 事故复盘（v0.4.2）

### 事故现象

v0.4.0 / v0.4.1 发布后，玩家在研究科技时触发闪退，崩溃转储均为 `Unhandled Exception C0000005`，`ExceptionInformation = [0x8, 0x7FF078]`（`0x8` = DEP 执行违规，故障地址落在栈区，意味着程序执行了跳向栈地址的间接调用）。

### 决定性指令级证据

反汇编崩溃线程返回地址（4.5.3 RVA `0xFC5BD2`）前方的调用点：

```asm
0xFC5BC1  lea  rcx, [rbp+0x78]
0xFC5BC5  call 0x141B50CE0      ; CFixedPoint::GetRounded（已被 hook）
0xFC5BCA  mov  edx, eax
0xFC5BCC  mov  rcx, r10         ; ← 调用后继续使用 r10
0xFC5BCF  call r11              ; ← 调用后继续使用 r11
0xFC5BD2  nop                   ; 崩溃栈返回地址
```

`stellaris.exe` 采用 MSVC `/GL`（LTCG，全程序优化）编译。编译器分析出 `GetRounded` 函数体实际只改写 `rax`/`rcx`/`rdx`，于是无视标准 x64 ABI 中 `r10`/`r11` 为 caller-saved 的规定，直接将活跃指针/函数指针放在 `r10`/`r11` 中跨调用复用。

普通 C 编写的 detour（尤其在首次调用写日志或触发心跳时）会改写 `r8`–`r11`，从而把调用方的 `r11` 破坏为栈地址，紧接着 `call r11` 引发 DEP 崩溃。

### 根治与验证

- 全部 19 个钩子改为安装 `src/detour_stubs.asm` 中的 MASM64 转发桩：入口保存 `rcx/rdx/r8-r11` + `xmm0-5`、转发第 5/6 栈参、调用 C `detour_*`、返回前原样恢复寄存器，使钩子破坏集恒为空集；
- 同时给 `recompute_max_hp` 的虚调用 `ship_size_of(design)` 增加了 vtable 合法性检查（要求首字段落在本映像区间），防止数据库加载期的栈上伪对象导致虚调用崩溃；
- 实机复测：地球联合国 3 局 + 游牧国家 1 局，各运行 30 游戏年，单局累计 hook 调用 **9950 万次**（`Atan2` 5100 万、`ApplyModifierMult` 3125 万、`GetRounded` 625 万），0 崩溃。

---

## 4. 关键症状的根因与验证证据

### 4.1 「护盾上限塌成 0」的三步根因

1. 高倍率 mod 使护盾加算修正真值越过 `INT64_MAX / 1e5 = 92233720368547`（约 92 万亿游戏单位），游戏乘法拆分路径 wrap 成负数；
2. `CShipSize::GetModifierValue` 对带掩码位（`mask >> 5 & 1`）的修正类型执行 `if (v < 0) v = 0`，将负值夹成 `0`；
3. 最终上限 `(base + 0) × factor = 0`，表现为护盾完全归零。

实测同一台异常舰船：装甲加算项为 `11000000000`，护盾加算项为 `0`，而护盾乘算项高达 `1000000000000000`（`1e10` 倍）。启用「`add_carries_value` 且 `add_in == 0` 且倍率 ≥ `1e7` → 封顶 `INT64_MAX`」判据后，异常舰船护盾由 `0` 恢复为 `92233720368547`，装甲/船体零误报。

### 4.2 船体上限未建模的三段条件加法与安全裁定

逐段比对 Linux `CalcMaxHitPoints` 与 Windows 对应函数后确认，船体上限比护盾/装甲多出三段条件累加，当前重算配方未建模（填 0）：
- `0x1ca/0x1cb`（4.5.x 编号；4.6.0 为 `0x1d6/0x1d7`）：舰队虚函数 `[0x60]()` 非零且 `CFleet::IsInFriendlyTerritory` 为真；
- `0x1ed`：`CShipSize` 标志位 `& 0x40`；
- `0x1ee` + 按尺寸选择的 `0x1ef..0x1f2`：同一标志位 `& 0x40`。

安全分析与裁定：三段均为加法，漏算只会让重算偏小，而回写闸门仅在游戏值呈 wrap 特征时才封顶到 `INT64_MAX`（固定天花板，不受漏算影响）。唯一理论边界窗口是「真值为负且 `sat != v`」，按实机裁定该场景下舰船本身已损毁不会重算，暂不额外收紧。

### 4.3 面板「伤害」只影响 UI 显示的三条证据

1. 面板调度器（4.5.2 `FUN_1411519f0`）将 `CalcAverageDamagePerDay` 的结果写入栈上临时槽 `local_res8` 后返回状态码 `1`，数值不流出到战斗状态；
2. 全部 8 个调用点均属于 UI / Tooltip 层（引用 `HEADER`/`TOTAL_VALUE`/`GROWTH_THRESHOLD_BASE_TOOLTIP` 等提示串），无任何战斗函数；
3. 实战伤害结算走 `TakeDamage`/`DealDamage` 独立链路，读取武器组件原始参数。

### 4.4 `ship_size_max_hp` 的端到端对照实验（4.5.2）

在测试 mod 中将原版护卫舰 `max_hitpoints` 设为 `1e14`（定点真值 `1e19`，预期 wrap 后为 `1e19 - 2^64 = -8446744073709551616`）：
- 无插件（`stl launch --no-plugins`）：设计界面显示 **`-84467440737095.51`**；
- 启用 `satfix` 回写模式：日志逐位命中 `-8446744073709551616 -> 9223372036854775807`，设计界面显示 **`92233720368547.75`**。

### 4.5 回写路径的 A/B 端到端证明（`GetRounded`）

同一构建脚本仅切换 `-Replace` 开关，活体探针测试 `GetRounded`：

| 输入 | 影子模式 (`REPLACE=0`) | 回写模式 (`REPLACE=1`) | 说明 |
| --- | :---: | :---: | --- |
| `123456` | `1` | `1` | 正常值不干预 |
| `9223372036854725807` | `92233720368547` | `92233720368547` | 上界最后安全值 |
| `9223372036854725808` | `-92233720368547` | **`+92233720368547`** | 上界首个溢出值被纠正 |
| `INT64_MAX` | `-92233720368547` | **`+92233720368547`** | 极值被纠正 |
| `INT64_MIN` | `+92233720368547` | **`-92233720368547`** | 下界溢出被纠正 |

### 4.6 两个「非缺口」的证伪结论

- **`cfx_get_rounded64`**：在全镜像字节搜索 `GetRounded` 前 24 字节仅出现 1 次。MSVC COMDAT 折叠将函数体完全相同的 `GetRounded` 与 `GetRounded64` 合并为同一地址，一个钩子同时覆盖两者。
- **`cfx_safe_sqrt_int`（`SafeSqrt(long long)`）**：Linux 侧唯一调用点在 `MTTHModifyNumber` 的 `case 0xf`；Windows 同函数（4.5.2 `FUN_14033fd20`）的 `case 0xf` 先检查 `*param_1 > -1`（否则直接报错返回），再直接将 `CFixedPoint*` 传给引用重载 `SafeSqrt(CFixedPoint const&)`，不存在整数转定点的 `p * 100000` 溢出步骤，MSVC 根本不生成该重载。

---

## 5. 跨版本演进与地址对照（4.5.2 → 4.5.3 → 4.6.0）

| Key | 4.5.2 (`0x6ABEAA3F`) | 4.5.3 (`0x6AE49C1B`) | 4.6.0 (`0x6AF6BDEC`) | 4.6.0 定位方式 / 变更摘要 |
| --- | :---: | :---: | :---: | --- |
| `cfx_get_rounded` | `0x01B4C170` | `0x01B50CE0` | `0x01CFF460` | 掩码字节全等（49/49） |
| `cfx_to_fp15` | `0x01B4C0A0` | `0x01B50C10` | `0x01CFF360` | 掩码字节全等（87/87） |
| `cfx_get_rounded_fp15` | `0x01B4C100` | `0x01B50C70` | `0x01CFF3C0` | 常量+簇间距（`+0x60`）；4.6 游戏侧新增自愈饱和钳位 |
| `cfx_round_to` | `0x01B4C1B0` | `0x01B50D20` | `0x01CFF4A0` | 掩码字节全等，`.pdata` 长度 282 相同 |
| `cfx_atan2` | `0x01B4C2D0` | `0x01B50E40` | `0x01CFF5C0` | 掩码字节全等（810B） |
| `cfx_sqrt` | `0x01B489D0` | `0x01B4D540` | `0x01CFBC90` | 掩码字节全等，长度 686 |
| `cfx_safe_sqrt` | `0x01B4C600` | `0x01B51170` | `0x01CFF8F0` | 掩码字节全等，长度 573 |
| `apply_mul_cfx` | `0x0036DF80` | `0x0036E990` | `0x004025F0` | 调用者法（`CalcStarbaseCapacity` 两次调用） |
| `apply_mul_fp15` | `0x0036E0A0` | `0x0036EAB0` | `0x00402730` | 紧邻 `apply_mul_cfx` + fp15 内联特征 |
| `var_multiply` | `0x01777F00` | `0x0177C660` | `0x018E8E40` | 独占诊断串唯一命中；4.6 改 token 哈希表，停用影子复算 |
| `var_add` | `0x01777800` | `0x0177BF60` | `0x018E83D0` | 共被调集合 + 纯加法写回 |
| `mpe15` | `0x00A0A4A0` | `0x00A0E4E0` | `0x00BAE130` | 掩码字节全等 |
| `mpe7` | `0x00A0A610` | `0x00A0E650` | `0x00BAE2A0` | 掩码字节全等 |
| `hull_max` | `0x00A112A0` | `0x00A152E0` | `0x00BB4A60` | `mov r9d, 0x20/0x21` 唯一命中；船级表 `0x2A2BCA4` |
| `shield_max` | `0x00A11D80` | `0x00A15DC0` | `0x00BB52E0` | `mov r9d, 0x30/0x31` 唯一命中；船级表 `0x2A2BD1C` |
| `armor_max` | `0x00A12910` | `0x00A16950` | `0x00BB5CD0` | `mov r9d, 0x26/0x27` 唯一命中；船级表 `0x2A2BCE0` |
| `damage_per_day` | `0x00A14C60` | `0x00A18CA0` | `0x00BB7D70` | 7/7 ModifierType 有序序列唯一命中 |
| `diplo_weight` | `0x00838670` | `0x00839B40` | `0x00916BA0` | 掩码一致率 0.9952 + `.pdata` 五块 `43/74/524/5/20` |
| `ship_size_max_hp` | `0x00D2B6E0` | `0x00D30A70` | `0x00E42660` | 三条独占报错串；4.6 `+0x6b8` 待活体复核暂不回写 |
| *`access_var_pointer`* | `0x009F7DF0` | `0x009F99B0` | `0x00B00910` | 4.6 第二参改为 `uint16` token（停用） |
| *`cvars_get`* | `0x00227390` | `0x002272C0` | `0x00295C10` | 掩码字节全等（4.6 变量效果链已不调用） |
| *`cvars_set`* | `0x007AAE10` | `0x007AC110` | `0x0088D260` | 4.6 改 token 键控写回（停用） |
| *`cfp_getvalue`* | `0x0034D500` | `0x0034DF70` | `0x003E3CF0` | 大 switch 魔数集 + 调用点（停用） |
| *`ship_size_of`* | `0x0030E990` | `0x0030F330` | `0x003AEA80` | 掩码字节全等（69B） |
| *`modifier_value`* | `0x00D29DD0` | `0x00D2F160` | `0x00E40D40` | 掩码字节全等（312B）；元数据表改为指针 `0x2A29CF0` 间接寻址 |

更详细的逐目标文字证据与实机调用统计请分别查阅 [`../tools/gen_targets_win.py`](../tools/gen_targets_win.py) 与 [`../EVIDENCE_live_gameplay.txt`](../EVIDENCE_live_gameplay.txt)。
