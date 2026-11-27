# tools/relocate —— 游戏更新后的地址重定位工具链

当 Stellaris 发布新版本、`python tools\gen_targets_win.py --check` 报告 PE 时间戳或序言签名漂移时，使用本目录脚本将全部 25 个目标（19 个钩子 + 6 个辅助函数）在新版 `stellaris.exe` 中重新对准并核验。

---

## 两种升级场景的打法

- **小版本更新（如 4.5.2 → 4.5.3）**：绝大多数函数体未改，主流程走「提取旧字节 → 掩码字节扫描 → `.pdata` 复核 → 指令形状/调用点补漏 → Ghidra 反编译交叉核对」。
- **内容大版本更新（如 4.5.3 → 4.6.0）**：约一半函数因逻辑或布局变更无法直接字节命中；先用掩码扫描捞回不变的那批，其余目标使用 **`locate46.py`**，按 `AGENTS.md` 标准流程结合**新版 Linux 反编译**（提取最新 ModifierType 枚举、独占串、常量与调用者关系）在 Windows `.text` / `.pdata` 上逐一确证，并同步排查枚举位移、全局表寻址方式与结构偏移变化。

---

## 脚本与档案文件说明

### 1. 通用字节比对与复核链（4.5.2 → 4.5.3 建立，4.6.0 复用）

| 文件 | 作用 | 输入 | 输出 |
| --- | --- | --- | --- |
| `probe_old_bytes.py` | 用 pyghidra 只读打开 4.5.2 Ghidra 工程，导出 25 个目标的整段机器码 | `_analysis/stellaris-c452` | `old_bytes_452.json` |
| `probe_old_bytes_453.py` | 同上，从 4.5.3 Ghidra 工程导出机器码，供 4.6.0 重定位作基线 | `_analysis/stellaris-c453` | `old_bytes_453.json` |
| `scan_in_new_exe.py` | 用 Capstone 将 `call`/`jmp` 的 `rel32` 和 RIP 相对寻址 `disp32` 标记为通配，逐字节扫描新版 `.text` | `old_bytes_*.json` + 新 exe | `scan_453.json` / `scan_46.json` |
| `verify_pdata.py` | 读取 PE `.pdata` 异常表，独立复核候选是否为编译器认定的函数起点并比对长度 | `scan_*.json` + 新 exe | 终端报告 |
| `instr_match.py` | 当字节扫描失配时，退回**指令形状相似度**（助记符 + 操作数种类 + 寄存器名，折叠立即数/位移） | `old_bytes_*.json` + 新 exe | 终端候选排名 |
| `callcheck.py` | 读调用点：将候选函数的 `call` 目标序列与旧构建逐位对齐，核验身份与 ABI | 手填新地址 | 终端报告 |
| `decomp_453.py` | 在新构建的 Ghidra 工程里针对新地址独立反编译 | `_analysis/stellaris-c453` | `decomp_453.json` |
| `compare_decomp.py` | 折叠 `FUN_` 地址与常量后比对新旧反编译文本相似度 | `decomp_*.json` + 旧 dump | 终端相似度表 |

### 2. 大版本综合工具箱（4.6.0 新增）

| 文件 | 作用 |
| --- | --- |
| `locate46.py` | 轻量单文件 PE / 反汇编 / Linux 4.6 dump 检索工具箱（依赖 `pefile`、`capstone`），不依赖 Ghidra 即可快速完成绝大部分大版本定位 |

`locate46.py` 常用子命令（在仓库根目录运行，可用 `--exe` / `--dump` 覆盖默认路径）：

```powershell
# 1) 查看 PE .pdata 概况，或查询某个 RVA 所属函数及是否为函数起点
python satfix-win/tools/relocate/locate46.py pdata
python satfix-win/tools/relocate/locate46.py pdata --rva 0x1CFF460

# 2) 反汇编 / 查看原始字节 / 反查调用者
python satfix-win/tools/relocate/locate46.py dis --rva 0x1CFF460 --len 96
python satfix-win/tools/relocate/locate46.py bytes --rva 0x1CFF460 --len 64
python satfix-win/tools/relocate/locate46.py callers --rva 0x1CFF460

# 3) 按立即数（如 ModifierType 组合）扫描新 exe
python satfix-win/tools/relocate/locate46.py scan-imm --imm 0x20,0x21

# 4) 给 Linux 4.6 反编译 dump 建索引并按符号名查看参考函数体
python satfix-win/tools/relocate/locate46.py index
python satfix-win/tools/relocate/locate46.py linux --name CalcMaxHitPoints --body
```

### 3. 历史记录 JSON 文件

`old_bytes_452.json`、`old_bytes_453.json`、`scan_453.json`、`scan_46.json`、`decomp_453.json` 均为各版本重定位的静态档案，用于跨版本差异回溯，不参与 DLL 构建。

---

## 落表与注意事项

1. **脚本路径**：脚本头部的 exe、Ghidra 工程与 Linux dump 路径默认指向开发机路径，换机运行前请修改常量或通过 CLI 参数覆写。
2. **不参与构建**：本目录脚本均不由 `build.ps1` 调用。
3. **落表与复核要求**：
   - 脚本只负责产出候选与机器级证据；确认后需将新 RVA 与证据写入 `satfix-win/tools/gen_targets_win.py`（如 4.6.0 使用 `RVA_46` / `EVIDENCE_46` 覆盖表），再运行 `python satfix-win\tools\gen_targets_win.py` 重新生成头文件；
   - **除了函数地址，大版本还必须逐项复核**：`ModifierType` 枚举编号、元数据表寻址方式（静态表 vs 指针间接寻址）、舰船等级修正表 RVA 与项数、以及所有硬编码结构偏移（未完成活体复核的偏移必须先关闭回写开关）；
   - 全部目标必须经调用点核对 ABI，并完成实机 `stl launch` 装载与 `首次调用` 验证。
