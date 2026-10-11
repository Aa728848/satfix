# satfix —— 给 Stellaris 的定点算术加饱和处理

| 文件 | 作用 |
| --- | --- |
| `stl_fix.hpp` | 三个定点方言 + 几个精确饱和参考实现 |
| `test_stl_fix.cpp` | 离线对拍，必须先全过 |
| `sat_guard.cpp` | shk hook：2 个修正出口 + 9 个 CFixedPoint 成员 |
| `satfix_targets.generated.hpp` | 自动生成，勿手改（16 个目标 + 版本串） |
| `third_party/EirinMath-1.5.2/` | eirin 头文件（来自 GitHub release） |
| `build.sh` | 一键：读配置 → 校验地址漂移 → 编对拍 → 编 hook |
| `tools/configure.sh` | 写 `satfix.conf`，自动探测或指定群星目录 |
| `tools/find_stellaris.py` | 按 Steam 库/环境变量自动定位群星 |
| `tools/gen_targets.py` | 从二进制算 hook 地址，生成上面的头文件 |
| `tools/fetch_eirin.sh` | 拉取 EirinMath 的 release 到 `third_party/` |
| `test/run_abi_check.sh` | ABI 回归：用假符号验证 hook 没写坏返回值、影子不误报 |

没有任何脚本硬编码群星路径，见第 4 节。

---

## 0. 实机日志分析（2026-10-09，第一次跑）

启动方式 `LD_PRELOAD=./sat_guard.so ./cream.sh ./stellaris 2> /tmp/satfix.log`，
日志 735 行。hook 装上了 10/11 个，但收集到的 500 条 EVENT 全是垃圾。两个问题。

### 问题 1（严重）：`operator fpml` 的返回 ABI 搞错了

日志里所有 EVENT 都是 `op_fp15`，而且 `game=` 是常数 `140736661709400`
（≈ 0x7FFxxxxxxxx，一个栈地址），`x=0` 时 `game` 也一样。游戏返回值根本不是返回值。

根因是 ABI：`CFixedPoint::operator fpml::fixed_point<...,15>() const` 返回类类型，走
sret（RDI 是返回槽，RSI 是 this）。反编译写得很清楚：

```c
CFixedPoint *operator_cast_to_fixed_point(CFixedPoint *this, long *param_1)
{ *(long *)this = ...; return this; }         // this 就是返回槽
```

我原来把它当成 RAX 返回 + 第一个参数是 this，影子读的是返回槽里未初始化的垃圾。已修，
并补了 `test/run_abi_check.sh` 做回归。这条测试反向验证过：把错误的 ABI 塞回去，它会报
2 条误报并失败。

### 问题 2（噪音）：非游戏进程也在跑 hook

`cream.sh` 是个 bash 脚本，会 `cp` 三个 so、再 `LD_PRELOAD=... "$@"`。
`LD_PRELOAD` 被子进程继承，于是 bash/cp/rm 每个进程都加载 sat_guard 并各打 11 行
失败信息，日志里同一段重复了 11 次。

已修：加 `/proc/self/exe` 判断，非 `stellaris` 进程直接静默退出（`SATFIX_VERBOSE=1`
可看一行说明）。离线测试用 `SATFIX_FORCE=1` 绕过这个检查。

### 附带确认

- 游戏确实按预期被 hook：成功那批的地址是 `0x55eebff79700` 这种带随机基址的形式。顺带纠正 hooklib README 里「Stellaris 是 ET_EXEC 非 PIE」的说法：`readelf -h` 显示是 PIE（ET_DYN），hooklib 的 `resolve_from_elf` 已经会加基址，所以 mangled 名解析照常工作。但不要把 `nm` 出来的地址当运行时地址硬编码，这就是日志里「0x1d9d700 不在本进程映射里」的原因（兜底路径按设计被跳过了）。
- `CFixedPoint::SafeSqrt(long long)` 一度装不上，报 `[shk] rel8 越界，放弃`。它的序言是 `push %rax; test %rdi,%rdi; jle rel8`，蹦床复制到远处后 rel8 够不到原目标。已修，细节见下一节。

### rel8 → rel32 加宽（hooklib 改动）

`hooklib/shk.hpp` 的蹦床原来只做 1:1 拷贝 + 原地修正位移，碰到 `jle rel8` 这种短跳
就放弃安装。现在改成先规划输出布局再逐条发射：

| 原指令 | 加宽后 | 长度 |
| --- | --- | --- |
| `jcc rel8`（2字节，`0x70..0x7F`） | `0F 8x rel32` | 2 → 6 |
| `jmp rel8`（2字节，`0xEB`） | `E9 rel32` | 2 → 5 |
| `loop/jrcxz`（`0xE0..0xE3`） | 无 rel32 形式，保持原样 | — |

加宽后所有后续指令在蹦床里的偏移都会变，所以每条分支的位移都按新位置 + 新长度重算；
`rip` 相对寻址、`rel32` 分支照旧修正。改的是蹦床副本，原函数一个字节都没动。

回归验证（`test/mock_stellaris.cpp` 里放了一个序言形状完全一样的假函数）：

```
开加宽：  [shk] reloc src=4 dst=4 in=2 out=6 kind=1 …   → 11/11 装上
关加宽：  [shk] rel8 越界…放弃                          → SafeSqrt 装不上（旧行为）
```

### 第二次运行（2026-10-09 12:55）

```
[satfix] 共装上 11/11 个 hook
[satfix] 未装上: CFixedPoint::SafeSqrt(long long)
[satfix]   ↑ 已知原因：该函数序言是 `push; test; jle rel8`…
EVENT 条数 = 0
```

这次注入是成功的。那两行 `未装上` 说的是同一个东西，也就是 11 个里唯一的 1 个
`SafeSqrt(long long)` 的 rel8 限制。日志也从 735 行降到 83 行，子进程不再刷屏。

但 `EVENT = 0` 有两种可能，光看日志分不清：一段时间里引擎算的都对（没溢出，这是预期
结果），或者 hook 根本没被调用过（日志显示游戏只走到 DLC/mod 挂载阶段就结束了，
还没进主菜单/读档/战斗）。

为此加了「首次调用」心跳，有界输出，最多 11 行，默认开：

```
[satfix] 首次调用: ApplyModifierMult(cfx)
[satfix] 首次调用: GetRounded()
...
```

只要看到某一行，就说明那个 hook 真的在被调用。想更详细可以开周期汇总：

```bash
SATFIX_HEARTBEAT=200000 LD_PRELOAD=./sat_guard.so ./cream.sh ./stellaris 2> /tmp/satfix.log
```

每 20 万次调用打一次分类计数 + 累计溢出数。

## 1. 群星有没有 Vulkan

没有，只有 OpenGL。Stellaris 4.5.2 的 Linux 版没有 Vulkan 渲染后端，引擎用 OpenGL。
证据（都可在 `stellaris_4.5.2_source.cpp` 与二进制里复核）：

1. 游戏自己的窗口/上下文创建只用 OpenGL。`CApplication::CreateApplicationWindow`（反编译 7580706–7580821）里是 `SDL_Init(SDL_INIT_VIDEO)` → 一串 `SDL_GL_SetAttribute(...)`（上下文版本、depth/stencil、多重采样、profile mask）→ `SDL_CreateWindow(...)`，整个函数没有一处 `SDL_Vulkan_*` 调用。
2. 引擎从不调用 Vulkan API。整个反编译产物里 `vkCreateInstance` / `vkEnumeratePhysicalDevices` / `vkQueueSubmit` 之类的调用数为 0。
3. 二进制里的 Vulkan 痕迹全是 SDL 自带的。`SDL_Vulkan_CreateSurface` / `LoadLibrary` / `GetInstanceExtensions`、`X11_Vulkan_*`、`Wayland_Vulkan_*`、`"Could not enumerate Vulkan physical devices"` 这些字符串属于 SDL2 自己的 Vulkan 视频/窗口 API，SDL2 全平台默认编译进去，不代表游戏使用。
4. 链接层面，`ldd stellaris` 里是 `libGL.so.1 / libGLX.so.0 / libGLdispatch.so.0 / libX11.so.6`，没有 libvulkan。
5. `settings.txt` 里的 `graphics { renderer=2 }` 是引擎自己的枚举，取值含义未逆清。但 GL 上下文的创建是无条件的，它不是「切 Vulkan」的开关。

所以不要指望通过配置或启动参数让群星跑 Vulkan。这对 satfix 没影响，我们做的是 CPU 侧的定点算术。

## 2. 游戏的三个定点方言（4.5.2 反编译确认）

| 游戏类型 | 存储 | 进制 | 1.0 = | 乘法形式 |
| --- | --- | --- | --- | --- |
| `CFixedPoint` | int64 | 十进制 | `100000` | `(v*m)/100000`，带拆分回退 |
| `fpml::fixed_point<long long,48,15>` | int64 | 二进制 | `2^15` | `v*m >> 15` |
| `fpml::fixed_point<long long,56,7>` | int64 | 二进制 | `2^7` | `v*m >> 7` |

依据是 `CFixedPoint::operator fpml::fixed_point<...>()`（反编译 8599271）的
`(x%100000)*0x40000000/0xC3500000 + (x/100000)*0x8000`，`0x8000 = 2^15`；以及
`NCombatRules::CalcMilitaryPower` 里的 `*0x4000/12800000 + ...*0x80`，`0x80 = 2^7`。

`fpml` 那两个方言和 `eirin::fixed_num` 编码完全一致，换实例化参数即可
（`fpml<...,15>` → `fixed_num<int64_t,__int128,15,false>`）。只有 `CFixedPoint`
是十进制，需要 `stl_fix.hpp` 里那 30 行适配。

## 3. 「溢出」的实测结论

`CFixedPoint` 的乘法不是单纯的 `(a*b)/100000`，它有两条路径：

```c
if (|v| <= 3037000499 && |m| <= 3037000499)   // 中间积一定放得下
    return (v * m) / 100000;
else {                                        // 精确等价的拆分
    X = max(v,m); Y = min(v,m);               // 有符号比较
    return ((X % 100000) * Y) / 100000 + (X / 100000) * Y;
}
```

拆分是精确变形，所以溢出边界被推后了。200 万组随机实测：

```
安全域（真值可表示 且 拆分首项不溢出）199 万组 -> 游戏与饱和实现 100% 逐位一致
其余 61.9 万组游戏结果 != 精确饱和值
  其中 11.9 万组是「真值其实放得下、但游戏仍然算错」
```

两个失败成因（`v`/`m` 是存储值，除以 1e5 才是游戏单位）：

- **(a) 真值本身超出 int64**（需 `|v·m| > 9.2e23`）：引擎 wrap，饱和即正解；
- **(b) 真值可表示但拆分首项 `(X%100000)*Y` 先溢出**（需 `|Y| > 9.2e13` ≈ 9.2 亿游戏单位）：引擎本可以算对却算错。

所以「值大就一定溢出」是错判。原版量级离阈值很远，要不要做取决于你的 mod。

### 一个已确凿的溢出实例（在游戏自己的函数里）

`CFixedPoint::GetRounded() const` 是 `x>=0 ? (x+50000)/100000 : -((50000-x)/100000)`，
`x + 50000` 会溢出。实测（`test_stl_fix` 第 6 节）：

```
INT64_MAX 的 GetRounded: 原式=-92233720368547  饱和=92233720368547
```

游戏把一个巨大的正数四舍五入成了负数。不依赖任何 mod 数值假设，可复现。

反过来的例子是证明安全：`operator fpml::fixed_point<...,15>()` 溢出不了。fp15 的
实数上限 2^48 ≈ 2.8e14 大于 int64 量程换算出的 9.2e13，对应 hook 不会触发。

## 4. 编译 / 运行（全部走配置，无硬编码路径）

先配置一次，把群星目录固化下来：

```bash
cd satfix
tools/configure.sh                    # 自动探测（读 Steam libraryfolders.vdf）
tools/configure.sh /path/to/Stellaris # 或手动指定游戏根目录
tools/configure.sh --show             # 看当前生效值
tools/configure.sh --clean            # 删掉 satfix.conf，回到自动探测
```

它生成 `satfix.conf`（本地文件，见 `.gitignore`）：

```
STELLARIS_GAME_DIR=/.../steamapps/common/Stellaris
STELLARIS_BIN=/.../steamapps/common/Stellaris/stellaris
```

优先级是环境变量 > `satfix.conf` > 自动探测，所以临时换目标不用改文件：

```bash
BIN=/other/path/stellaris ./build.sh
EIRIN_INC=/path/to/eirin/include ./build.sh     # 换 eirin（默认 third_party）
EIRIN_DEV_REPO=~/somewhere/fixed32 ./build.sh   # 换本地开发仓库的兜底位置
```

然后构建、运行：

```bash
./build.sh              # 影子模式；自动校验地址漂移并在需要时重新生成
./build.sh replace      # 打开"检出问题时回写饱和值"
GEN=1 ./build.sh        # 强制重新生成地址表

./test_stl_fix          # 离线对拍，必须先全过

# 启动
cd "$(dirname "$(python3 tools/find_stellaris.py)")"
LD_PRELOAD=$PWD/../../.../sat_guard.so ./stellaris
# Steam 启动：launch options 里写
#   LD_PRELOAD=<satfix>/sat_guard.so %command%
```

不带 `replace` 的影子模式只记录不改数值，用来在开发期观察真实数据。发布给用户的
构建用 `./build.sh replace`，也就是回写模式。

## 5. hook 清单（16 个目标）与策略

| # | 目标 | 策略 | 说明 |
| --- | --- | --- | --- |
| 1 | `CModifier::ApplyModifierMult(CFixedPoint&, ...)` | EXACT | 所有乘法修正的唯一出口；in-place + 返回实际倍率 |
| 2 | `CModifier::ApplyModifierMult(fpml<...,15>&, ...)` | EXACT | 同上，乘法在 2^15 编码上做 |
| 3 | `CFixedPoint::GetRounded() const` | EXACT | 已证实会在 `x→INT64_MAX` 时返回负数 |
| 4 | `CFixedPoint::GetRounded64() const` | EXACT | 与 3 函数体完全相同 |
| 5 | `CFixedPoint::operator fpml::fixed_point<...,15>() const` | EXACT | 已证明不会溢出，保留作证明 |
| 6 | `CFixedPoint::SafeSqrt(long long)` | INPUT_GUARD | `p*100000` 溢出（`p > 92233720368547`） |
| 7 | `CFixedPoint::Sqrt() const` | INPUT_GUARD | 负数输入会被当巨大无符号数迭代 |
| 8 | `CFixedPoint::SafeSqrt() const` | OBSERVE | 只记录负输入 |
| 9 | `CFixedPoint::RoundTo(CFixedPoint const&)` | OBSERVE | 记录 `divisor==0` 与 `v+divisor/2` 溢出 |
| 10 | `CFixedPoint::Atan2(CFixedPoint const&, CFixedPoint const&)` | OBSERVE | 记录参数平方会溢出的量级 |
| 11 | `CFixedPoint::GetRounded(fpml<...,15> const&)` | OBSERVE | 记录换算回十进制会溢出的量级 |
| 12 | `CMultiplyVariableEffect::ExecuteActual(CEventScope&) const` | EXACT | 变量乘法：`(v0*m)/100000`，裸乘无饱和，mod 完全可控 |
| 13 | `CAddVariableEffect::ExecuteActual(CEventScope&) const` | EXACT | 变量加法，顺手一起 |
| 14 | `NCombatRules::CalcMilitaryPowerExponent(fpml<...,15>, fpml<...,15>)` | OBSERVE | 舰队实力指数（pow 链），sret + 指针参数 |
| 15 | `NCombatRules::CalcMilitaryPowerExponent(fpml<...,7>, fpml<...,7>)` | OBSERVE | 同上，另一编码 |
| 16 | `CPopJob::CalcDiplomaticWeight(CPopGroup const&) const` | OBSERVE | 外交权重；用户实测后期舰队部分极易溢出 |

三种策略的区别：EXACT 有精确饱和参考实现，逐位比对，可替换；INPUT_GUARD 是危险在
输入域，先把输入夹到安全域再调原函数；OBSERVE 只能判定是否进入危险域，只记日志。

Sqrt 和 Atan2 那几个 OBSERVE 不替换，是因为 Sqrt 是牛顿迭代、Atan2 是多项式逼近，
重写出逐位等价的参考实现成本高又容易出错。它们的价值是暴露调用量级，等日志证明有
实际问题再处理。

### 12/13 变量系统的影子怎么算

刻意不重写逻辑，而是调用游戏自己的辅助函数复算（只解析，不 hook）：

```c
which = this + 0xb8                                  // CString 变量名
vars  = AccessVariablePointer(scope, which)          // CVariables*
v0    = CVariables::GetVariable(vars, which)         // 调用前
m     = CFixedPointVariableValue::GetValue(this+0xe8, scope)   // 乘数/增量表达式
--- 调原函数 ---
v1    = CVariables::GetVariable(vars, which)         // 调用后
影子  = cfx::mul(v0, m)                              // 或 saturating_add(v0, m)
```

四个辅助函数的 mangled 名都写死在 `install_hooks()` 里，任何一个解析失败就退化成纯
透传（只计数、不动数值），不会因为签名猜错而炸游戏。

### 14/15/16 为什么是 OBSERVE

- 14/15 是 pow：等价饱和实现要自己写幂运算，和 Sqrt/Atan2 同类风险。判据是输入的
  中间积会撑爆 int64，命中就记一行，先看真实数据。
- 16 的判据很硬：外交权重不可能为负（经济/科技/舰队各项加权求和），所以返回负数或
  量级离谱（> 1e17）就几乎必然是 wrap，不需要复算。

`CFixedPoint` 的 `operator+ - * /` 没有符号、全是内联。`nm` 里 `CFixedPoint::` 只有
这 9 个成员，反编译里 `... / 100000` 就地展开 2551 处，所以全引擎饱和做不到，只能抓关口。

日志格式：

```
[satfix] EVENT ApplyModifierMult  type=28 flag=0 v0=... mult=... game=... sat=...
[satfix] EVENT GetRounded        x=9223372036854775807 game=-92233720368547 sat=92233720368547
```

## 6. 自动维护

### 6.1 hook 地址：`tools/gen_targets.py`

```bash
tools/gen_targets.py           # 不传参数 = 用 satfix.conf / 自动探测（build.sh 已自动调用）
tools/gen_targets.py /path/to/stellaris
tools/gen_targets.py --check   # 只比对；漂移则 exit 1
tools/gen_targets.py --list    # 打印解析结果
```

读 `nm`/`nm -D` 建 mangled 名到地址的映射，提取二进制版本串，生成 X-macro 头文件。
加新目标只需在脚本顶部 `TARGETS` 列表加一行，`sat_guard.cpp` 不用动地址。

运行时的解析顺序是 `dlsym` → `/proc/self/exe` 符号表 → 生成头文件里的兜底地址。
用兜底地址之前会确认它在本进程映射里，避免误 preload 到别的程序时写坏内存。Stellaris
有 18 万+ 动态符号，正常情况 dlsym 就命中。

### 6.2 eirin 依赖：`tools/fetch_eirin.sh`

```bash
tools/fetch_eirin.sh           # 拉最新 release
tools/fetch_eirin.sh 1.5.3     # 指定版本
tools/fetch_eirin.sh --list    # 看有哪些版本
```

### 6.3 ABI 回归：`test/run_abi_check.sh`

`build.sh` 会自动跑，失败就中止构建。它用一组假符号（`test/mock_stellaris.cpp`）复现被
hook 的函数，检查两件事：返回值原样正确（抓 detour 写坏返回寄存器或参数），以及安全
输入下不产生 EVENT（抓 detour 读错参数，比如把 sret 当 this）。

不需要开游戏，约 1 秒。每次改 hook 签名都该先过这个，否则就要浪费一次游戏启动。

---

## 7. 需要做的验证

**① 跑离线对拍（5 秒）**

```bash
cd satfix && ./build.sh && ./test_stl_fix
```

要求 `failures=0`。不通过说明 `eirin` 版本或编译器不同，先别往下走。

**② 配置群星目录（一次）**

```bash
tools/configure.sh          # 或 tools/configure.sh /path/to/Stellaris
```

之后 `./build.sh` 不需要任何参数。换机器或换 Steam 库重跑一次即可。

**③ 冒烟：确认 16 个 hook 都装上了**

按第 4 节启动，stderr 应有 16 行 `hooked ...` + `共装上 16/16 个 hook`（rel8 加宽之后
`SafeSqrt(long long)` 也能装上）。出现 `符号解析失败` 或 `FAILED to hook`，
跑 `GEN=1 ./build.sh`。

`cream.sh` 的子进程不会再刷屏，非 stellaris 进程静默跳过。

**④ 影子模式实机跑，收集日志**

```bash
LD_PRELOAD=$PWD/sat_guard.so ./stellaris 2> /tmp/satfix.log
grep -c EVENT /tmp/satfix.log
grep EVENT /tmp/satfix.log | sort | uniq -c | sort -rn | head
```

重点跑数值最大的武器、舰队和后期存档。按结果决定下一步：

- 一条 EVENT 都没有：到此为止，别开 `replace`。
- 只有 ApplyModifierMult / GetRounded 类（EXACT）：开 `./build.sh replace`，最稳的一档。
- 出现 Sqrt/Atan2/RoundTo 类（OBSERVE）：说明有调用进了危险域，把日志发出来，再决定加权夹还是专门写参考实现。

**⑤ 开 replace 之前**

备份存档，先用新存档验证，并记住只影响被 hook 的这 11 个函数，内联副本不受影响。

**⑥ 游戏更新后**

`./build.sh` 会自动 `--check`，有漂移就重新生成。若某符号被 LTO 掉、`--list` 显示
`MISS`，需要手工找替代符号。

## 8. 已知限制

- 群星没有 Vulkan 后端（第 1 节），渲染侧没有可干预空间。
- `CFixedPoint` 的算术运算符全部内联，无法整体替换，只能抓关口。
- 3 个 OBSERVE 目标只观测不修复。
- `shk` 的安装不是线程安全的，必须在主循环之前装（当前用全局对象构造，满足）。
- 只对 hook 到的调用点生效，同一段内联代码在别处的副本不受影响。
- `fpml` 是 `(v*m)>>15`（向下取整），`CFixedPoint` 是 `/100000`（向零截断），负数时差 1 ULP，代码里分开处理。
- 影子比较依赖「`ApplyModifierMult` 返回实际倍率」这一行为（4.5.2 反编译 962783 / 962939 确认），若引擎改了约定，需要同步改 `hook_apply_mul_*`。