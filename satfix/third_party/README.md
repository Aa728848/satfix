# third_party —— 第三方依赖（Linux 侧）

## EirinMath-1.5.2

- **上游仓库**：<https://github.com/Koishi-Satori/EirinMath>
- **当前版本**：`v1.5.2`（源码 tarball `refs/tags/v1.5.2.tar.gz`，MIT 许可，见子目录 `LICENSE`）
- **头文件路径**：`EirinMath-1.5.2/include/eirin/`

`satfix/stl_fix.hpp` 使用其中的 `fixed_num`、`saturating_add/sub/mul/div` 与 `saturating_cast` 作为二进制 `fpml` 方言与 128 位饱和算术的后端。

### 更新与路径覆盖

通过脚本拉取新版本：

```bash
cd satfix
./tools/fetch_eirin.sh           # 拉取最新 release
./tools/fetch_eirin.sh 1.5.3     # 拉取指定版本
./tools/fetch_eirin.sh --list    # 列出上游可用版本
```

`build.sh` 查找 `eirin/numeric.hpp` 的优先级为：
1. 环境变量 `EIRIN_INC`；
2. `satfix/third_party/*/include`（默认即本目录下的 `EirinMath-1.5.2/include`）；
3. 本地开发仓库兜底 `$EIRIN_DEV_REPO/include`（默认 `$HOME/CLionProjects/fixed32/include`）。

如需临时指向自定义版本，直接传入环境变量即可，无需修改源码：

```bash
EIRIN_INC=/path/to/EirinMath/include ./build.sh
```
