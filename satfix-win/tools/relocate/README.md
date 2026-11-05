# tools/relocate —— 游戏更新后重新对准目标地址的工具链

这套脚本是 4.5.2 -> 4.5.3 时写出来的，用途：**游戏发新版、`gen_targets_win.py --check` 报漂移之后**，
用旧构建的机器码当密码本，把 25 个目标（19 个钩子 + 6 个辅助函数）在新 exe 里重新定位。
流程与结论记录在 `../../README.md` 的「游戏更新后」一节。

## 顺序

| 脚本 | 作用 | 输入 | 输出 |
| --- | --- | --- | --- |
| `probe_old_bytes.py` | 用 pyghidra 只读打开**旧构建**的 Ghidra 工程，把目标函数机器码整段取出来 | 旧工程 `_analysis/stellaris-c452` | 本文档目录的同名 json |
| `scan_in_new_exe.py` | capstone 标记 rel32/disp32 为通配，其余字节比对新 exe 的 `.text` | `old_bytes_452.json` + 新 exe | `scan_453.json` |
| `verify_pdata.py` | 用 PE `.pdata` 异常表独立复核「候选是不是函数起点」，并比对函数长度 | `scan_453.json` | 终端报告 |
| `instr_match.py` | 字节失配时退回**指令形状相似度**（助记符 + 操作数种类 + 寄存器） | `old_bytes_452.json` | 终端排名 |
| `callcheck.py` | 读调用点：把已定位函数的 `call` 目标序列与旧构建逐位对齐（ABI/身份判据） | 手填新地址 | 终端报告 |
| `decomp_453.py` | 给新构建跑 Ghidra 分析后，在**新地址**上反编译函数体（独立复核，不复用字节比对） | `_analysis/stellaris-c453` | `decomp_453.json` |
| `compare_decomp.py` | 新旧反编译文本归一化后比对（`FUN_` 地址、常量常数都折叠） | 上面两个 json + 旧 dump | 终端相似度表 |

## 注意

- 脚本里的路径是**这台机器上的绝对路径**（新 exe、Ghidra 工程、旧 dump）。换机器要改开头的常量。
- `old_bytes_452.json` / `decomp_453.json` 是**记录**，不是输入时必须重新生成的东西：
  它们同时是「4.5.2 与 4.5.3 在这 25 个函数上差多少」的存档，出问题可以拿来对。
- 这些脚本不参与构建，也不被 `build.ps1` 调用。
- 判定标准仍然是 `gen_targets_win.py` 的 `CONFIRMED` / `HELPERS` 表：脚本只负责**给出候选与证据**，
  落表时要连证据一起写进去。
