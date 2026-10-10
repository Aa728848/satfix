# satfix —— Stellaris 定点溢出守卫

把 Stellaris 的定点算术接上**饱和处理**，让后期存档里那些被 mod 推到天文数字的
数值不再静默 wrap 成负数。

同一个守卫有两份实现，语义对齐：

| 目录 | 平台 | 注入方式 |
|---|---|---|
| [`satfix/`](satfix/) | Linux | `LD_PRELOAD` 预加载 `.so`，按 mangled 名 `dlsym` 定位 |
| [`satfix-win/`](satfix-win/) | Windows | Stellaris Launcher 的 DLL 插件，按 **RVA + 序言签名** 定位 |

## 为什么值得做

Stellaris 的定点数用 `int64` 存，1.0 记作 `100000`。上限是 `9.22e18 / 1e5 ≈ 9.2e13`
游戏单位。原版离这个上限极远，但 mod 堆叠乘法很容易越过 —— 越过之后**不报错**，
直接 wrap 成负数：海军容量变成负的、资源扣成天文数字、外交权重突然为负。

这类 bug 难查，因为它不崩、不报错，只是数值不对。

## 现状

**Windows 侧 17/17 目标全部实机验证**（Linux 侧 19 个 hook 目标在 Windows 上全部覆盖）：

| | EXACT（能真正修数值） | INPUT_GUARD | OBSERVE |
|---|---|---|---|
| Linux | 6 | 2 | 11 |
| Windows | 6 | 1 | 10 |

- EXACT 集合两个平台**完全相同**：`cfx_get_rounded`、`cfx_to_fp15`、
  两个 `ApplyModifierMult`、`var_add`、`var_multiply`。
- `cfx_get_rounded64` 因 MSVC 的 COMDAT 折叠与 `cfx_get_rounded` 同地址，一个钩子覆盖两者。
- `cfx_safe_sqrt_int` 在 Windows 侧**无对应代码**（MSVC 不生成该重载的那步换算），
  详见 `satfix-win/README.md` §0.1.11。

一局后期 mod 存档的实测：**2390 万次调用，0 条真实分歧**，游戏全程稳定。

## 快速开始

### Windows

```powershell
cd satfix-win
.\build.ps1                     # 编译 + 跑 4 套自测（25/25 + 58/58 + 14组 + 24/24）
.\build.ps1 -Replace            # 额外打开回写（会改数值，见下）
```

然后用 [Stellaris Launcher](https://github.com/Yidhar/stellaris-launcher) 安装：

```powershell
stl plugin install .\plugin --link
stl plugin enable satfix
stl launch
```

日志在 `plugin\logs\satfix.log`。

### Linux

```bash
cd satfix
./build.sh
LD_PRELOAD=$PWD/sat_guard.so ./stellaris
```

## 两种模式（重要）

默认编译出来是**影子模式**（`REPLACE=0`）：只**检出并记录**分歧，**不改任何数值**。

要让插件真正把 wrap 掉的值纠正成饱和值，必须用 `-Replace`（Linux 侧 `SATFIX_REPLACE=1`）
重新编译。这是**编译期**开关，故意不做成配置项 —— 避免手动注入时误改存档。

回写路径有端到端验证（同一构建脚本只差一个开关）：

| 构建 | `GetRounded(INT64_MAX)` 返回 | 含义 |
|---|---|---|
| `REPLACE=0` | `-92233720368547` | 游戏 wrap 后的值（就是那个 bug） |
| `REPLACE=1` | `+92233720368547` | **饱和值（被纠正了）** |

## 定位方法（Windows 侧）

`stellaris.exe` 没有 PDB、只导出 110 个符号、没有任何 C++ 符号，
所以**不能**像 Linux 那样按 mangled 名解析。`satfix-win/` 用的办法是
**RVA + 16 字节序言签名**，签名不匹配就停用该目标并写日志 —— 不盲目读写内存。

把 17 个目标找出来用了四类判据，都记录在 `satfix-win/tools/gen_targets_win.py`
的 `CONFIRMED` 表里（每条带证据）：

1. **独占字符串** —— 例如 `multiply_variable: variable %s is not set…` 唯一命中一个函数；
2. **类型表索引常量集** —— `armor_max` 的 `0x15fec/0x15ff8/0x160a8` 三常量同现，
   扫过 110843 个函数块**命中数 = 1**；
3. **已确证函数的 helper 调用组合** —— 先提取 helper RVA，再找同类调用者；
4. **NDefines 名字 thunk** —— 从 exe 的 `.rdata` 取出 `NDefines::<组>::<名字>` 字符串，
   反汇编引用它的 thunk，`r9` 里就是该 define 的全局地址，
   于是「名字 → 全局地址」被直接读出来，再用「谁读这个全局」定位函数。

同时记录了几条**被证伪**的思路，免得后来人重走：
- Linux 里的**立即数**指纹对 MSVC 不可移植（GCC 用立即数的地方 MSVC 常用指令）；
- Linux 的**成员偏移**不能直接搬到 MSVC（如 `+0xb8→+0xc0`、`+0x808→+0x8b0`）；
- 按 Linux 的**函数间距**找邻居不可靠。

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

## 限制

- 只对**已确证 RVA** 的版本生效。游戏更新后签名校验会挡下全部目标并写日志，
  需要重新确证地址（`tools/gen_targets_win.py --check` 能报告漂移）。
- OBSERVE 类目标**只检出、不修改** —— 它们与 Linux 侧同策略。
  pow 链（军力指数）的等价饱和实现风险高，故意不做。
- 正常游玩不会触发任何 EVENT：原版量级离溢出阈值差十几个数量级。
  要看到效果需要 mod 把数值推到 ~9.2e17。

## 许可

MIT，见 [LICENSE](LICENSE)。非官方项目，与 Paradox Interactive 无关。
