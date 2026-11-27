# satfix —— Stellaris 定点算术溢出守卫

后期装了高倍率 mod 之后，群星（Stellaris）内部的定点数值容易越过 64 位整数上限，然后**不报错、不崩溃，悄悄翻成负数或塌成 0**：

- 护盾 / 装甲 / 船体上限塌成 `0` 或显示成负数；
- 舰船详情面板里的「伤害」变成天文数字的负数；
- 舰船设计界面的基础「船体值」变成负数；
- 海军容量、资源扣减、外交权重、脚本变量或修正倍率在极端堆叠下发生回绕（wrap）。

`satfix` 在关键算术与结算关口注入饱和处理，让越界数值停在格式天花板（约 **92 万亿游戏单位**，`INT64_MAX / 1e5`），而不是回绕成损坏数值。

---

## 平台实现与当前状态

仓库包含两个平台实现与一套底层 hook 库：

| 目录 | 平台 | 形态与定位方式 | 当前适配版本 | 状态 |
| --- | --- | --- | --- | --- |
| [`satfix-win/`](satfix-win/) | **Windows (x64)** | [Stellaris Launcher](https://github.com/Yidhar/stellaris-launcher) 合规 DLL 插件；硬编码 RVA + 16 字节序言签名校验 | **Cygnus v4.6.0**（`0x6AF6BDEC`，插件 `v0.5.0`） | 主力维护、实机验证 |
| [`satfix/`](satfix/) | **Linux (x86-64)** | `LD_PRELOAD` 共享库（`sat_guard.so`）；按 mangled 符号名 `dlsym` / ELF 符号表定位 | Cygnus v4.5.2（`32709cf254...`） | 基础实现，滞后于 Windows 侧 |
| [`hooklib/`](hooklib/) | **Linux (x86-64)** | 零依赖单头文件内联 hook 库 `shk.hpp` | 通用 ELF x86-64 | Linux 侧底层依赖 |

### 覆盖策略一览

所有 hook 目标按干预方式分为三类：

- **EXACT**：拥有饱和参考实现或硬判据，可逐位比对并在回写模式下纠正数值；
- **INPUT_GUARD**：溢出发生在输入域，先将输入夹取到安全域再调用原函数；
- **OBSERVE**：仅检测是否进入危险域并记录日志，不改数值。

| 平台 | 已装目标 | EXACT | INPUT_GUARD | OBSERVE | 备注 |
| --- | :---: | :---: | :---: | :---: | --- |
| **Windows (`v0.5.0`)** | **19**（+6 辅助函数） | 9\* | 1 | 9 | `cfx_get_rounded64` 因 MSVC COMDAT 折叠与 `cfx_get_rounded` 共用同一钩子；`cfx_safe_sqrt_int` 经证实 Windows 侧不生成该重载 |
| **Linux (`v4.5.2`)** | **19**（+6 辅助函数 + ImGui 调试窗） | 8 | 2 | 9 | 尚未同步 Windows 侧新增的 `damage_per_day`、`ship_size_max_hp`、船级表重算及 4.6.0 适配 |

> \* **4.6.0 主动安全闸**：Windows `v0.5.0` 中有两处为防止版本升级误改而主动收紧的设计：
> 1. `ship_size_max_hp`（策略标为 `kExact`）依赖的 `CShipSize + 0x6b8` 偏移在 4.6.0 上尚未完成活体复核，当前版本暂仅记录 EVENT、暂停回写；
> 2. 4.6.0 将脚本变量底层改为 token 键控哈希表，`var_multiply` / `var_add` 的旧四步读回链已停用，当前仅计数。

详细目标清单与地址见 [`satfix-win/README.md`](satfix-win/README.md) 与 [`satfix/README.md`](satfix/README.md)。

---

## 溢出为什么会发生

Stellaris 内部使用三种 64 位定点方言，其中最常见的是十进制 `CFixedPoint`（`int64_t`，`1.0 = 100000`）：

- 表示上限为 `INT64_MAX / 100000 ≈ 9.22 × 10^13` 游戏单位（约 92.2 万亿）。
- 原版游戏数值离这个天花板差十几个数量级，但后期高倍率 mod 叠加修正后，乘法、累加或四舍五入（如 `GetRounded` 中的 `x + 50000`）会直接越界回绕成负数。
- 部分读取原语（如 `CShipSize::GetModifierValue`）还会把负值夹成 `0`，导致「护盾加成溢出 → 负值 → 被夹成 0 → 护盾上限塌成 0」。
- 由于 `CFixedPoint` 的基础四则运算符几乎全部内联（反编译中 `/ 100000` 展开达数千处），无法全局替换，因此本项目的策略是在**修正出口、结算函数与非内联算术成员**这些关键关口做饱和守卫。

---

## 快速开始

### Windows 玩家：直接安装发布版

> 仓库内不提交预编译的 `satfix.dll`。普通玩家请直接下载发布包。

1. 从 [GitHub Releases](https://github.com/Aa728848/satfix/releases) 下载最新 `satfix-v*.zip`（可选用同名 `.sha256` 校验完整性）。
2. 通过 [Stellaris Launcher](https://github.com/Yidhar/stellaris-launcher) 安装并启用，或将 zip 内容解压到：
   ```
   Documents\Paradox Interactive\Stellaris\plugins\satfix\
   ```
3. 通过启动器启动游戏。运行时日志位于插件目录的 `logs\satfix.log`，配置文件位于 `config\satfix.ini`（修改后每 2 秒自动热重载，无需重启游戏）。

清单已配置 `update.github` 与 `update.asset`，支持通过启动器自动检查更新。

### Windows 开发者：从源码构建

需要 **Visual Studio 2022 Build Tools**（x64 C++ 工具链含 `cl.exe` / `ml64.exe` + Windows SDK）与 **Python 3**（可选 `pefile` 用于校验 exe 时间戳）。

```powershell
cd satfix-win

.\build.ps1                # 影子模式：只记录日志、不改数值（开发自测用）
.\build.ps1 -Replace       # 回写模式：检出溢出即改回饱和值（发布版用）
.\build.ps1 -TestOnly      # 仅编译并运行 winhook 单元测试
```

`build.ps1` 会依次完成汇编寄存器保全桩（`detour_stubs.asm`）、编译 DLL、运行 3 套原生离线自测 + 组装 `dist\satfix\` + 运行插件包合规检查，任意一项失败都会中止。

使用 Stellaris Launcher 进行本地开发联调：

```powershell
stl plugin install .\plugin --link     # 链接开发目录，重编译后立即生效
stl plugin enable satfix
stl launch
```

### Linux 构建与运行

```bash
cd satfix
./tools/configure.sh                   # 自动探测 Steam 目录，或传入 /path/to/Stellaris
./build.sh                             # 影子模式（含地址漂移检查与 ABI 回归）
./build.sh replace                     # 回写模式
./test_stl_fix                         # 运行离线算术对拍，要求 failures=0

# 启动游戏
LD_PRELOAD="$PWD/sat_guard.so" /path/to/Stellaris/stellaris
# 或在 Steam 启动选项中设置：
#   LD_PRELOAD=/abs/path/to/satfix/sat_guard.so %command%
```

---

## 两种构建模式：回写 vs 影子

为了防止开发调试或手动注入时误改存档，**是否写回数值是编译期开关**，不暴露为运行时配置项：

| 模式 | Windows 构建 | Linux 构建 | 二进制标记 | 行为与用途 |
| --- | --- | --- | --- | --- |
| **回写模式** | `.\build.ps1 -Replace` | `./build.sh replace` | `satfix-build-mode:write-back` | 检出溢出时将数值改写回饱和值；**正式发布版本** |
| **影子模式** | `.\build.ps1` | `./build.sh` | `satfix-build-mode:shadow` | 仅检出并记日志，绝不改写数值；**开发/观察用** |

确认任意 `satfix.dll` 的构建模式无需依赖记忆：可直接搜索二进制内的 `satfix-build-mode:` 字符串，或查看 `logs\satfix.log` 第一行（例如 `satfix-win 0.5.0  REPLACE=1  satfix-build-mode:write-back`）。

---

## 发布与自动更新（Windows）

```powershell
cd satfix-win
.\build.ps1 -Replace
.\tools\package_release.ps1
# 产物：release\satfix-v<version>.zip、.sha256、.zip.notes.md
```

打包脚本从 `plugin\stl-plugin.json` 读取 `version`，并在出包前强制校验四件事：
1. DLL 必须包含 `satfix-build-mode:write-back` 标记（默认拒绝打包影子版）；
2. 发布目录不含 `config\`、`logs\`；
3. 清单声明的 `config[].default` 文件存在于包内；
4. [`satfix-win/RELEASE_NOTES.md`](satfix-win/RELEASE_NOTES.md) 中存在对应的 `## v<version>` 段落（该文件是发布说明的唯一来源，脚本会自动抽出生成 `.notes.md`）。

打标签并发布（标签必须为 `v` + 清单 `version`）：

```powershell
git tag v<version> && git push origin v<version>
gh release create v<version> release\satfix-v<version>.zip release\satfix-v<version>.zip.sha256 `
    --title "satfix v<version>" --notes-file release\satfix-v<version>.zip.notes.md
```

---

## 仓库结构

```text
.
├── AGENTS.md                           AI 与开发者的硬性工程约束
├── README.md                           本文件（项目总览）
├── hooklib/                            Linux x86-64 单头文件 hook 引擎（shk.hpp）
├── satfix/                             Linux 侧实现（LD_PRELOAD）
│   ├── sat_guard.cpp                   hook 入口与各目标 detour
│   ├── stl_fix.hpp                     定点算术与饱和参考实现（基于 EirinMath）
│   ├── satfix_targets.generated.hpp    自动生成的符号/地址表
│   ├── debug_ui.hpp                    可选 ImGui 调试窗口（实验性）
│   ├── tools/                          目录探测、目标表生成、依赖拉取脚本
│   ├── test/                           离线算术对拍与 ABI 回归测试
│   └── third_party/EirinMath-1.5.2/    上游定点库（MIT）
└── satfix-win/                         Windows 侧实现（Stellaris Launcher DLL 插件）
    ├── src/
    │   ├── sat_guard_win.cpp           插件本体（DllMain、配置、日志、主线程泵、detour）
    │   ├── detour_stubs.asm            LTCG 寄存器保全汇编转发桩（19 个钩子）
    │   └── satfix_targets_win.generated.hpp  自动生成的 RVA + 16B 序言签名表
    ├── winhook.hpp                     Windows x64 hook 引擎（5B E9 + 蹦床 + 线程挂起补丁）
    ├── satfix128.hpp / stl_fix_win.hpp / satfix_decision.hpp  128 位饱和算术与判定自检
    ├── plugin/                         开发联调目录（stl-plugin.json + defaults/satfix.ini）
    ├── test/                           3 套原生离线测试（hook 引擎、算术对拍、宿主加载管线）
    ├── tools/                          目标生成、包合规检查、打包、dump 索引与指纹工具
    │   └── relocate/                   游戏版本更新后的跨版本地址重定位工具链
    ├── docs/ENGINEERING_NOTES.md       逆向定位方法、ABI/LTCG 踩坑录与版本演进档案
    ├── build.ps1                       一键构建、自测与组装发布目录
    └── RELEASE_NOTES.md                GitHub Release 发布说明唯一来源
```

---

## 文档导航

| 文档 | 内容与受众 |
| --- | --- |
| [`satfix-win/README.md`](satfix-win/README.md) | Windows 插件完整说明：架构、19 个目标现状、修复机制、配置项、测试与发布 |
| [`satfix-win/docs/ENGINEERING_NOTES.md`](satfix-win/docs/ENGINEERING_NOTES.md) | Windows 深度工程档案：跨平台定位法、6 次 ABI/偏移踩坑、LTCG 寄存器契约、版本迁移记录 |
| [`satfix-win/tools/relocate/README.md`](satfix-win/tools/relocate/README.md) | 游戏更新后的地址重定位操作手册与脚本说明 |
| [`satfix-win/RELEASE_NOTES.md`](satfix-win/RELEASE_NOTES.md) | 各版本更新日志（发布打包脚本唯一数据源） |
| [`satfix/README.md`](satfix/README.md) | Linux 侧实现、定点溢出实测结论、目标清单与运行指南 |
| [`hooklib/README.md`](hooklib/README.md) | `shk.hpp` 零依赖 Linux hook 库文档 |
| [`AGENTS.md`](AGENTS.md) | 跨平台反编译对照、ABI 核对、LTCG 破坏集与插件合规等硬性开发约束 |

---

## 已知限制与免责声明

- **严格绑定游戏构建**：Windows 版依靠 PE 时间戳与 16 字节序言签名双重校验；游戏更新后不匹配的目标会被自动跳过并记录日志，确保不乱读写内存，但需要重新定位并更新插件。
- **无法覆盖全部内联算术**：`CFixedPoint` 的基础运算符广泛内联，插件只能守住关键关口，无法替换所有内联展开副本。
- **封顶值的物理上限**：`INT64_MAX`（约 92.2 万亿游戏单位）是游戏自身定点格式的物理天花板，超越上限时只能饱和停留于此值。
- **回写策略偏保守**：宁可漏报、绝不误改；OBSERVE 类目标（如舰队实力幂函数 `CalcMilitaryPowerExponent`、外交权重等）仅做观测，不主动篡改数值。
- **建议备份存档**：使用回写版前建议备份重要存档；本项目尚未与其它第三方原生 DLL 插件做全面并发兼容测试。

## 许可

MIT License，见 [`LICENSE`](LICENSE)。第三方组件 `EirinMath` 遵循其自带 MIT 许可。本项目为非官方社区工具，与 Paradox Interactive 无关。
