# AGENTS.md —— 给在这个仓库里干活的 AI / 人

本文件是**工作方式的硬约束**，不是介绍。开工前先读完。

---

## 0. 这个仓库是什么

`satfix` —— 给 Stellaris 的定点算术（`CFixedPoint`）加饱和处理的溢出守卫。

同一份逻辑有两个平台实现，**改一个必须考虑另一个**：

| 目录 | 平台 | 形态 |
| --- | --- | --- |
| `satfix/` | Linux | `LD_PRELOAD` 共享库（`sat_guard.so`），靠 `dlsym` + 符号名定位 |
| `satfix-win/` | Windows | Stellaris Launcher 插件 DLL（`satfix.dll`），靠硬编码 RVA + 序言签名定位 |
| `hooklib/` | 共用 | Linux 侧的 hook 引擎（`shk`）；Windows 侧是自带的 `winhook.hpp` |

游戏版本：**Cygnus v4.5.2**，`stellaris.exe` build 时间戳 `0x6ABEAA3F`。

---

## 1. ★ 最重要的一条：必须结合 Linux 与 Windows 两套反编译源码库

**这是本项目所有定位工作的基础，不要绕过它。**

### 为什么

Windows 的 `stellaris.exe` 被 strip 过：

| 项 | 值 |
| --- | --- |
| 导出符号 | 110 个（几乎全是 PhysicsFS，**拿不到任何游戏函数**） |
| C++ 符号 | **无** |
| PDB | **无** |
| `.pdata` | 134803 个函数，**只有地址区间，没有名字** |
| RTTI | 1269 条类名（只能给类，给不了非虚成员地址） |

而 **Linux 版二进制保留了完整符号表**（139641 个函数块，99.9993% 有名）。

两份 dump 是**同一个 build**（同 commit、同版本串），所以**同一个函数在两边的「形状」是一致的**：
函数体逻辑、独占常量、ModifierType 序列、调用结构 —— 这些都能跨平台对照。

### 源码库在哪（**不在本仓库内**，体量太大）

相对于本仓库上级目录：

| 文件 | 大小 | 说明 |
| --- | --- | --- |
| `../stellaris_4.5.2_source.cpp` | 339 MB | **Linux 4.5.2 反编译，有完整符号名** —— 主力参考 |
| `../_analysis/stellaris_4.5.2_win_source.cpp` | 173 MB | Windows 4.5.2 反编译，**只有 `FUN_xxxxxxxx`** |
| `../_analysis/stellaris_4.5.2_win_symbolized.cpp` | 173 MB | 上一份的「回填符号名」版（见下方警告） |
| `../stellaris_4.5_source.cpp` / `../_analysis/stellaris_4.5_win_source.cpp` | 304/173 MB | 4.5.0 版本，做版本漂移对照用 |
| `../_analysis/win_linux_mapping_final_452.json` | 1.1 MB | 10186 对 `FUN_ → Linux 名` 映射 |
| `../_analysis/_ndefines_thunks.json` | 158 KB | 2369 条 `(NDefines 名, 组, 全局地址)` |

dump 格式（两份一致，`// ==== <name> End ====` 分隔）：

```
<body 在前>
// ============ FUN_140a14c60 End ===============
<空行 ×3>
```

**解析要点**：函数体在**分隔行之前**。写解析脚本时容易 off-by-one（把名字配到下一个函数体上），
第一次读某函数时**先打印它的签名行确认**（`longlong * FUN_xxx(...)`）。

### 标准定位流程（照这个做）

1. **在 Linux dump 里按符号名找到目标函数**，读它的完整函数体。
2. **提取跨平台指纹**，按可靠性排序：
   - **独占常量**（最强）：只在少数函数里出现的魔数。例：
     `0xb50679d3` 是 `CalcAverageDamagePerDay` 独有的安全界；
     `0x1614c/0x16158/0x16208/0x162b8` 是护盾专用的 ModifierType 集合。
   - **ModifierType 序列**（很强）：函数依次取哪些 `GetModifierValue` 的 type 号。
     实测 `0x3a/0x40/0x168/0x41/0x1d2/0x1d3/0x230` 这一串 7 个全同且同序，是决定性证据。
   - **结构偏移**：读 `param_2 + 0xNNN` 这种。**注意 MSVC 与 GCC 布局会不同**，只能当辅助。
   - **调用者/被调用者**：见下。
3. **在 Windows dump 里按指纹筛候选**，逐个读函数体确认。
4. **【必做】核对 ABI —— 看调用点，不是看函数体**（见 §2）。
5. 把结论加进 `satfix-win/tools/gen_targets_win.py` 的 `CONFIRMED` 表（格式 `(key, desc, rva, strat, sig, evidence)`，6 个字段），
   然后 `python tools/gen_targets_win.py` 重新生成头文件。

### 定位手段（按实战效果排序）

1. **调用者法** —— 用 Linux 侧「谁调用 X」的名单，去找 Windows 侧调用同一批函数的那个函数。
   `apply_mul_cfx`、`cfx_sqrt` 都是这么定出来的。
2. **NDefines 名字法** —— Paradox 的 `NDefines` 名字字符串存在于 exe 的 `.rdata`，
   扫 `.text` 找 rip-relative 引用，能读出「名字 → 全局地址」；
   再找「同时读这些全局」的函数。`diplo_weight`、`mpe15`/`mpe7` 靠它破局。
3. **片区扫** —— 已知函数常在同一个命名空间里连续排布。三个上限函数在 `0xA112A0`~`0xA12910`，
   于是扫 `0xA00000..0xA20000` 就找到了伤害函数 `0xA14C60`。**这条救过一次错误定位。**
4. **常量指纹** —— 见上。

### 已证伪的思路（别重走）

- **调用图传播**：精度只有 12–26%，不可用（枢纽函数吸票）。
- **字段偏移结构指纹**：单独用精度 ~18%。
- **按函数体形状找 `apply_mul_cfx`**：Windows 里有 75 个函数含同一套 CModifier 惯用法，常量分不开，必须看调用点。

---

## 2. ★ 第二条：函数体一样 ≠ ABI 一样

**每次都要看调用点确认参数含义。** 这不是理论风险，已经踩过多次：

| 踩坑 | 症状 | 原因 |
| --- | --- | --- |
| `FUN_14075a370` 被当成 `operator fpml` | 活体探针四个输入全返回同一常数 `1767657313` | 函数体一样，但 rdx 其实是个**缩放标量**，不是返回槽 |
| `cfx_to_fp15` | 第一次按「rdx=源、rcx=返回槽」写，探针全 0 | 参数顺序反了；正确是 `rcx=源, rdx=返回槽` |
| `mpe15` vs Linux | — | **参数顺序相反**（Linux 是 `(out, 指数, 底数)`，Windows 是 `(out, 底数, 指数)`） |
| `FUN_1403c2910` 被当成伤害函数 | 装了、调用 13000 次，但一个 EVENT 都没触发 | 它是「单件武器」那层；真正的伤害总计是 `0xA14C60` |
| `detour_max_hp` 读错返回位置 | 以为三个上限函数「返回全是 0」 | 实际是读错了位置；实机日志证明它们返回真实值 |

**教训**：写 detour 前，把调用点的 `FUN_xxx(args...)` 那一行读出来，逐个参数核对。

---

## 3. 本地化新目标的验收标准

一个目标只有满足这些才算「确证」，缺一不可：

1. **RVA 有依据**（调用点 / 独占常量 / 邻居位置，写进 `evidence` 字段）
2. **序言签名**已生成（`gen_targets_win.py` 自动从 exe 读 16 字节）
3. **ABI 有调用点证据**（不是靠函数体猜）
4. **实机验证**：`stl launch` 后日志里出现 `hooked <key> @ <addr>`，且**目标函数被实际调用**（`首次调用: <name>`）
5. **判据有实机证据**：要么抓到真实的 EVENT，要么用活体探针证明检出链通了

**「装上钩子」不等于「功能可用」** —— 必须看到调用计数在涨。

---

## 4. 构建 / 测试

### Windows（`satfix-win/`）

```powershell
cd satfix-win

.\build.ps1                # 影子模式（只记录，不改数值）—— 开发/测试用
.\build.ps1 -Replace       # ★ 回写模式（检出溢出就改回饱和值）—— 发布用
.\build.ps1 -TestOnly      # 只跑离线测试，不编 DLL
```

`build.ps1` 跑 4 套测试（25 / 58 / 14 组 / 24 项）。**必须全过**。

产物：
- `build/satfix.dll`
- `plugin/`（链接用的工作目录）
- `dist/satfix/`（发布包内容）

**两种模式是编译期开关**（`-Replace`），不是配置项 —— 故意如此，免得手动注入时误改存档。
二进制里带 marker，日志第一行会打印 `satfix-build-mode:write-back` 或 `:shadow`。

### 实机验证

```powershell
$stl = "$env:LOCALAPPDATA\Programs\Stellaris Launcher\stl.exe"
& $stl plugin install "<repo>\satfix-win\plugin" --link
& $stl launch
# 日志：<repo>\satfix-win\plugin\logs\satfix.log
```

- **`--link` 指向开发目录**：`config\`、`logs\` 会写在里面，正常。
- **改了 DLL 要先关游戏**，否则 `build.ps1` 复制失败（文件被占用）。
- 配置**热重载**（每 2 秒看一次修改时间），改 `config\satfix.ini` 不必重启游戏。
- `game_click.ps1` / `perf_probe.ps1` / `tick_probe.ps1` 是辅助脚本（截图、性能测量）。

### Linux（`satfix/`）

```bash
cd satfix
./build.sh              # 影子模式
./build.sh replace      # 回写模式
./test_stl_fix          # 离线对拍，必须先全过
```

**注意**：本机没有 Linux 工具链，`satfix/` 目前只能静态审查，不能构建验证。

---

## 5. 设计约定

### 策略三分类（`Strategy` 枚举）

| 策略 | 含义 |
| --- | --- |
| `kExact` | 有精确饱和参考实现，可逐位比对、可回写 |
| `kInputGuard` | 危险在输入域：先把输入夹到安全域再调原函数 |
| `kObserve` | 只判定「是否进入危险域」，只记日志 |

当前分布：**EXACT 8 / INPUT_GUARD 1 / OBSERVE 9**（合计 18）。
**这个数以 `src/satfix_targets_win.generated.hpp` 为准** —— 它由 `gen_targets_win.py` 生成，
手写的文档容易写错（本文件早期版本就写成过 7/1/10）。要核对：

```powershell
Select-String -Path satfix-win\src\satfix_targets_win.generated.hpp -Pattern ', k(Exact|Observe|InputGuard),' |
    Group-Object { $_.Line -replace '.*,\s*(k\w+),.*','$1' } | Select-Object Name,Count
```

### 回写闸门（重要）

**宁可漏报，不可误改。** 只在「游戏值本身呈 wrap 特征」时才回写：

- 负值（上限/伤害不可能为负）
- 或 `0` 而重算为正（护盾/装甲「加算被塌成 0」的现场）

正常值哪怕重算不等，也只记 NOTE 不改。理由：重算可能漏了条件性修正，
而漏项只会让重算**偏小** —— 偏小的一侧不会把正常值判成溢出，方向是安全的。

### 性能纪律

热路径函数被调用**百万到千万次**（`CalcMax*` 各约 810 万次/局，`ApplyModifierMult` 463 万次）。
所以：

- **能早退就早退**。例：所有回写分支都要求 `v <= 0`，那 `v > 0` 就直接 `return`，
  不必做 4~6 次游戏函数调用 + 扫 46 项修正表。
- **热路径别用 `safe_read`**。它每次都调 `VirtualQuery`（内核调用）。
  地址来自游戏传入指针的场合用 `whk::fast_read`（只 SEH 兜底）。
  来自我们解析的 RVA / 猜测偏移的，**仍然必须** `safe_read`。
- **诊断开关默认关**。任何逐调用的额外开销（原子加、格式化）都要能关掉。
- 已实测：一次「每调用都记日志」的诊断刷了 19899 行，把日志上限打满。

### 日志

上限 20000 行。事件类日志要**限流**（例如「按 design 指针只报一次」），
因为舰船详情面板会**每帧**重算。

---

## 6. 文档

| 文件 | 作用 |
| --- | --- |
| `satfix-win/README.md` | Windows 侧完整记录：目标清单、定位证据、踩坑 |
| `satfix/README.md` | Linux 侧记录 |
| `satfix-win/RELEASE_NOTES.md` | **发布说明的唯一来源**，被 `tools/package_release.ps1` 用正则解析 |
| `satfix-win/tools/gen_targets_win.py` | **目标的权威来源** —— 每个目标的 `evidence` 字段写在这里 |

**`RELEASE_NOTES.md` 不要随意改格式** —— 打包脚本靠 `## v<version>` 段落提取说明。
**`gen_targets_win.py` 的 `CONFIRMED` 表是唯一权威**，README 里的数字可能与它不同步，
有疑问**以 `gen_targets_win.py` 和生成的 `src/satfix_targets_win.generated.hpp` 为准**。

---

## 7. 必须遵守插件手册

Windows 侧不是普通 DLL，是 **Stellaris Launcher 插件**，必须满足规范：

> `stellaris-launcher/docs/PLUGIN_HANDBOOK.zh-CN.md`
> （英文版 `PLUGIN_HANDBOOK.md`；本仓库上级目录的 `stellaris-launcher/` 里）

**改 Windows 侧代码前，先读手册 §6（编写 DLL 的规则）与 §13（发布前检查清单）。**

### 硬性要求（§6，违反会导致崩溃/卡死/被拒）

| 条款 | 要求 | 本插件现状 |
| --- | --- | --- |
| 6.1 | `DllMain` 只创建线程；不等待、不 `LoadLibrary`、不碰引擎、不做文件/网络 | ✅ 只 `CreateThread` + `CloseHandle` |
| 6.2 | 从**自己模块地址**取插件路径；不用 CWD、不写死 `Documents\…` | ✅ `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` |
| 6.3 | 引擎函数只在游戏主线程调用 | ✅ detour 内只做原子写，重活推迟到主线程泵 |
| 6.4 | 原始内存读用 SEH 包住 | ✅ `whk::safe_read` / `fast_read` |
| 6.5 | detour 必须调原函数；不假设自己是唯一钩子；不恢复他人钩子 | ✅ `TypedHook::call()` |
| 6.6 | **不卸载自己**（不 `FreeLibraryAndExitThread`） | ✅ 源码中无调用 |
| 6.7 | 静态运行库 `/MT`；不弹控制台；只支持 x64 | ✅ `/MT`、无 `AllocConsole` |

**6.4 还有一条容易忽略的**：手册明确说「不要依赖 Linux 版反编译里的结构偏移，
Windows（MSVC）与 Linux（GCC）的对象布局不同」。本项目的做法是**偏移一律在 Windows
侧重新确证**（读函数体），Linux 侧只用来**指路**，不用来抄数值。

### 6.3 线程模型（最容易让游戏静默崩溃）

引擎代码**只能**在游戏主线程跑。本插件的模式：

- detour 里**只做原子写**（计数、置标志）
- 真正的活（读设置、写日志、解析）推迟到「主线程泵」—— 只在游戏自己进入被 hook 函数时触发

**不要**在自己的线程里调游戏函数。这条踩过坑：早期在 hook 里调
`CShipSize::GetName()`，因为它在 `CPdxTaskScheduler` 工作线程上被调用、
而本地化字符串池不是线程安全的 → **SEGV**。

### 清单（§4 / 附录 B）

`plugin/stl-plugin.json` 必须满足：

- `"schema": 2`
- `id` 合法且**与以前一致**（改 id 等于换一个插件，用户设置会丢）
- `version` 与 tag、发布说明标题一致
- `game.exe_timestamps` 列出所有测试过的构建（**注意它是嵌在 `game` 下的**，不是顶层）
- `config[].default` 指向的文件必须真的在包里
- 自动更新需要 `update.github` + `update.asset`

DLL 自己也要**再校验一次** PE 时间戳与序言签名（手册 §7），不匹配就跳过该目标并写日志 ——
这样在未列出的构建上（手动注入时）是**安全地不工作**，而不是乱读写内存。

### 包与发布（§10 / §13）

- zip 的内容**就是插件文件夹**；**不含** `config\`、`logs\`
- 标签 = `v` + `version`；附件名匹配 `update.asset`；附带 `.sha256`
- 正式发布（不是草稿、不是预发布）

**自检命令**：

```powershell
python satfix-win\tools\check_plugin_pkg.py     # 校验 dist\ 是否符合手册
```

> 注意：对 `plugin\`（开发链接目录）跑这个会报 `config\`/`logs\` 存在 —— 那是正常的，
> 该检查针对的是 `dist\` 发布目录。

---

## 8. 发布流程

```powershell
cd satfix-win
.\build.ps1 -Replace                    # 必须是回写模式
.\tools\package_release.ps1             # 校验 + 打包（版本号取自 stl-plugin.json）
```

`package_release.ps1` 的参数只有三个：`-OutDir`（默认 `release/`）、
`-Mode`（`write-back` / `shadow` / `any`，**默认 `write-back`**）、`-Exe`。
**版本号不通过参数传** —— 它从 `plugin/stl-plugin.json` 的 `version` 字段读。

打包脚本会检查：
- 包内**不含** `config\` / `logs\`（用户私有）
- 清单声明的 `config.default` 文件确实在包里
- **构建模式是 `write-back`**（影子模式默认被拒；要放行得显式 `-Mode any`）
- 从 `RELEASE_NOTES.md` 提取 `## v<version>` 段落生成 `<zip>.notes.md`

**tag 要自己打**（脚本不校验，只打印出建议的 `gh release create` 命令）：

```powershell
git tag v0.2.0 && git push origin v0.2.0
gh release create v0.2.0 satfix-v0.2.0.zip satfix-v0.2.0.zip.sha256 `
    --title "satfix v0.2.0" --notes-file satfix-v0.2.0.zip.notes.md
```

**版本号只在 `plugin/stl-plugin.json` 的 `version` 一处定义** —— 打包、tag、发布说明的
`## v<version>` 标题都要与它一致。

发布包：`github.com/Aa728848/satfix`，asset `satfix-*.zip`。

---

## 9. 反模式（出现即为错误）

1. **不看 Linux 源码就硬猜 Windows 函数** —— 这是本项目最贵的错误来源。
2. **靠映射表的名字当身份证明**。`win_linux_mapping_final_452.json` 的
   `confidence: "exact"` 只表示「字符串指纹唯一命中」，**不代表函数就是同名的那个**。
   实测反例：映射说 `FUN_1408b3700 = ApplyModifierMult`，实际是 modifier token 分发器。
3. **靠函数体猜 ABI**。必须看调用点。
4. **「钩子装上了」就宣布完成**。要看调用计数在涨、判据有实机证据。
5. **改回写路径却不留退路**。任何回写都要有明确的「何时不回写」闸门。
6. **在热路径里加重活**（`VirtualQuery`、字符串格式化、每调用一次日志）。
7. **只改一个平台**。两边的逻辑要同步；Windows 侧的常量/偏移**不要照抄** Linux 的，要重新确证。
8. **手改 `src/satfix_targets_win.generated.hpp`** —— 它是生成的。改 `tools/gen_targets_win.py`。

---

## 10. 快速上手

```powershell
# 1) 看当前目标清单与策略
#    没有 --list 这种开关；直接读生成的头文件，或看 gen_targets_win.py 的 CONFIRMED 表
Select-String -Path satfix-win\src\satfix_targets_win.generated.hpp -Pattern '^    \{"'

# 2) 校验 RVA/签名是否仍与目标 exe 匹配（游戏更新后先跑这个）
python satfix-win\tools\gen_targets_win.py --check

# 3) 构建 + 测试
cd satfix-win; .\build.ps1 -Replace
```

`gen_targets_win.py` 只有三个开关：`--exe`（目标 exe 路径）、`--out`（输出头文件）、
`--check`（只校验不写）。**不带参数就是重新生成**。

遇到「游戏更新后钩子全失效」：跑 `--check`，它比对 PE 时间戳与每个目标的序言签名，
不匹配会明确指出是哪个目标漂了。
