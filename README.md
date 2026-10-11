# satfix —— Stellaris 定点溢出守卫

给 Stellaris 的定点算术加饱和处理，让后期存档里被 mod 推到天文数字的数值停在上限，而不是静默 wrap 成负数。

两个平台各有一份实现，语义一致：

| 目录 | 平台 | 注入方式 |
|---|---|---|
| [`satfix/`](satfix/) | Linux | `LD_PRELOAD` 预加载 `.so`，按 mangled 名 `dlsym` 定位 |
| [`satfix-win/`](satfix-win/) | Windows | Stellaris Launcher 的 DLL 插件，按 RVA + 序言签名定位 |

## 溢出是怎么发生的

Stellaris 的定点数用 `int64` 存，1.0 记作 `100000`，上限约 `9.22e18 / 1e5 ≈ 9.2e13` 游戏单位。原版离这个上限极远，mod 堆叠乘法就很容易越过去。越过去之后游戏既不报错也不崩溃，直接 wrap 成负数：海军容量变成负的、资源扣成天文数字、外交权重突然为负。

这类 bug 难查，原因就在这里：它不崩、不报错，只是数值不对。

## 现状

Windows 侧 17 个目标全部实机验证通过（Linux 侧的 19 个 hook 目标在 Windows 上都有覆盖）：

| | EXACT（能真正修数值） | INPUT_GUARD | OBSERVE |
|---|---|---|---|
| Linux | 6 | 2 | 11 |
| Windows | 6 | 1 | 10 |

EXACT 集合两个平台完全相同：`cfx_get_rounded`、`cfx_to_fp15`、两个 `ApplyModifierMult`、`var_add`、`var_multiply`。

`cfx_get_rounded64` 因 MSVC 的 COMDAT 折叠与 `cfx_get_rounded` 同地址，一个钩子覆盖两者。`cfx_safe_sqrt_int` 在 Windows 侧没有对应代码（MSVC 不生成该重载里那步换算），详见 `satfix-win/README.md` §0.1.11。

一局后期 mod 存档的实测：2390 万次调用，0 条真实分歧，游戏全程稳定。

## 快速开始

### Windows

```powershell
cd satfix-win
.\build.ps1                     # 影子模式：编译 + 跑 4 套自测（25/25 + 58/58 + 14组 + 24/24）
.\build.ps1 -Replace            # 回写模式：发布用这个（会改数值，见下）
```

打发布包（按[插件手册](https://github.com/Yidhar/stellaris-launcher/blob/main/docs/PLUGIN_HANDBOOK.zh-CN.md)
§10 产出 zip + `.sha256`）：

```powershell
.\tools\package_release.ps1
```

然后用 [Stellaris Launcher](https://github.com/Yidhar/stellaris-launcher) 安装：

```powershell
stl plugin install .\plugin --link     # 开发：链接，重编译即生效
stl plugin enable satfix
stl launch
```

日志在 `plugin\logs\satfix.log`。也可以直接从
[Releases](https://github.com/Aa728848/satfix/releases) 下载 zip 解压到
`Documents\Paradox Interactive\Stellaris\plugins\satfix\`，或让启动器自动更新。

### Linux

```bash
cd satfix
./build.sh
LD_PRELOAD=$PWD/sat_guard.so ./stellaris
```

## 两种模式

发布给用户的是回写模式。影子模式只用于开发自测，不随发布包分发。

| 模式 | 编译 | 行为 | 用途 |
|---|---|---|---|
| 回写 | `-Replace` | 检出溢出时把值改写成饱和值 | 发布给用户的版本 |
| 影子 | 默认 | 只检出并记录，不改数值 | 开发自测 |

这是编译期开关（Linux 侧 `SATFIX_REPLACE=1`），故意不做成配置项，免得手动注入时误改存档。

确认手上那个 DLL 是哪种模式，不用靠记性：每种构建都会往二进制里打一个 marker，字节搜索即可，两种 DLL 大小几乎相同。

```
satfix-build-mode:write-back     回写
satfix-build-mode:shadow         影子
```

日志首行也会写出来：`satfix-win 0.2.0  REPLACE=1  satfix-build-mode:write-back`。
`tools/package_release.ps1` 默认要求 write-back，打错模式会直接拒绝打包。

回写路径有端到端验证，同一构建脚本只差一个开关：

| 构建 | `GetRounded(INT64_MAX)` 返回 | 含义 |
|---|---|---|
| shadow | `-92233720368547` | 游戏 wrap 后的值（就是那个 bug） |
| **write-back** | `+92233720368547` | **饱和值（被纠正了）** |

## Windows 侧怎么定位目标

`stellaris.exe` 没有 PDB、只导出 110 个符号、没有任何 C++ 符号，所以不能像 Linux
那样按 mangled 名解析。`satfix-win/` 用的办法是 RVA + 16 字节序言签名双重校验，
签名不匹配就停用该目标并写日志，不盲目读写内存。

17 个目标靠四类判据找出来，都记录在 `satfix-win/tools/gen_targets_win.py` 的
`CONFIRMED` 表里，每条带证据：

1. **独占字符串**，例如 `multiply_variable: variable %s is not set…` 唯一命中一个函数；
2. **类型表索引常量集**，例如 `armor_max` 的 `0x15fec/0x15ff8/0x160a8` 三常量同现，扫过 110843 个函数块命中数为 1；
3. **已确证函数的 helper 调用组合**，先提取 helper RVA，再找同类调用者；
4. **NDefines 名字 thunk**，从 exe 的 `.rdata` 取出 `NDefines::<组>::<名字>` 字符串，反汇编引用它的 thunk，`r9` 里就是该 define 的全局地址。名字到全局地址的对应直接读出来了，再用谁读这个全局去定位函数。

同时也记了几条被证伪的思路，免得后来人重走一遍：Linux 里的立即数指纹对 MSVC
不可移植（GCC 用立即数的地方 MSVC 常用指令），成员偏移不能直接搬（`+0xb8→+0xc0`、
`+0x808→+0x8b0`），按函数间距找邻居也不可靠。

## 目录结构

```
satfix/                      Linux 侧（LD_PRELOAD）
  sat_guard.cpp              插件本体
  satfix_targets.generated.hpp  目标地址表（由 tools/gen_targets.py 生成）
  stl_fix.hpp, debug_ui.hpp
  tools/                     目标表生成 / 二进制查找 / 构建辅助
  test/                      ABI 对拍（mock_stellaris + abi_check）
  docs/
  third_party/EirinMath-1.5.2/  MIT，见其自带 LICENSE

satfix-win/                  Windows 侧（Launcher DLL 插件）
  src/sat_guard_win.cpp      插件本体
  src/satfix_targets_win.generated.hpp  目标地址表（由 tools/gen_targets_win.py 生成）
  winhook.hpp                hook 引擎（5 字节 E9 rel32 + 蹦床 + 线程挂起式补丁）
  satfix128.hpp              128 位中间量（MSVC 无 __int128）
  stl_fix_win.hpp            定点算术与饱和参考实现
  satfix_decision.hpp        判定逻辑 + 14 组进程内自检向量
  tools/                     目标表生成 / dump 索引 / 指纹 / 调用者定位
  test/                      3 套自测（hook 引擎、离线对拍、插件管线）
  build.ps1                  一条命令：编译 + 4 套自测 + 打包
  EVIDENCE_live_gameplay.txt 实机证据（含每一轮的方法与被证伪的思路）
```

## 发布与自动更新

清单里已声明自动更新所需的字段：

```json
"update":   { "github": "Aa728848/satfix", "asset": "satfix-*.zip" },
"homepage": "https://github.com/Aa728848/satfix"
```

所以启动器插件页会对它检查更新。发布流程（手册 §10.2）：

```powershell
.\satfix-win\tools\package_release.ps1
#   产出 release\satfix-v<版本>.zip + .sha256 + .zip.notes.md
gh release create v<版本> <zip> <zip>.sha256 --notes-file <zip>.notes.md
```

标签必须等于 `v` + 清单里的 `version`，附件名要匹配 `update.asset`。

打包脚本会当场查四件事，任一不过就拒绝出包：

1. 标签 = `v` + `version`；
2. 包内没有 `config\`、`logs\`（手册 §10.1）；
3. DLL 的构建模式，默认要求 `write-back`，打出影子版会被拒；
4. `satfix-win/RELEASE_NOTES.md` 里有这个版本的那一节。

发布说明的唯一来源是 [`satfix-win/RELEASE_NOTES.md`](satfix-win/RELEASE_NOTES.md)，
脚本会抽出对应小节写成 `.notes.md`。不要在 GitHub 网页上直接改说明，下次发布会被覆盖，
而且没有版本记录。

> 仓库里不含预编译的 DLL（`satfix.dll` 被 gitignore）。
> 直接用请从 Releases 下载；自行编译需要 VS2022 BuildTools + Windows SDK。

## 合规性

本插件按 [插件手册 v2](https://github.com/Yidhar/stellaris-launcher/blob/main/docs/PLUGIN_HANDBOOK.zh-CN.md)
实现，逐条对照：

| 手册 | 要求 | 实现 |
|---|---|---|
| 6.1 | `DllMain` 只创建线程 | 只 `CreateThread`，不等待/不加载库/不碰引擎 |
| 6.2 | 从模块路径找插件文件夹 | `GetModuleHandleExW` + `GetModuleFileNameW` |
| 6.3 | 引擎代码只在游戏主线程 | detour 里只做原子写，重活丢给主线程泵 |
| 6.4 | 原始内存读取有 SEH | `winhook::safe_read`；坏指针停用该目标并记日志 |
| 6.5 | 钩子调原函数、不动他人钩子 | 蹦床转发；`uninstall` 只用于自测 |
| 6.6 | 不卸载自己 | 不调用 `FreeLibraryAndExitThread` |
| 6.7 | `/MT` 静态运行库、x64、不弹控制台 | `/MT`；x64；无 `AllocConsole` |
| 7 | 两层版本检查 | 清单列 `exe_timestamps` + DLL 自己比对 PE 时间戳与序言签名 |
| 8 | 读 `config\`、缺失用内置默认值、热重载 | 每 2 秒看修改时间 |
| 9.1 | 日志写 `logs\`、运行中可读、有上限 | 见下方说明 |
| 10.1 | 包内无 `config\`/`logs\` | `tools/check_plugin_pkg.py` 守着（23 项） |

有一处有意偏离手册（9.1）。手册建议 `_wfsopen(..., _SH_DENYWR)`，实测本机
`_wfopen_s` 与 `_SH_DENYWR` 都返回 `EACCES`，而 Win32 层
`CreateFileW(GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE)` 能正常读。所以改用
`_wsopen_s` + 显式 `_SH_DENYNO`，意图不变（允许游戏运行时读日志），手段按实测调整，
并由 `test_load_plugin` 的可读性断言守住。

## 限制

- 只对已确证 RVA 的版本生效。游戏更新后签名校验会挡下全部目标并写日志，需要重新确证地址（`tools/gen_targets_win.py --check` 能报告漂移）。
- OBSERVE 类目标只检出、不修改，与 Linux 侧同策略。pow 链（舰队实力）的等价饱和实现风险高，故意不做。
- 正常游玩不会触发任何 EVENT：原版量级离溢出阈值差十几个数量级。要看到效果需要 mod 把数值推到 ~9.2e17。

## 许可

MIT，见 [LICENSE](LICENSE)。非官方项目，与 Paradox Interactive 无关。