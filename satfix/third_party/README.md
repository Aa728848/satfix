# third_party

## EirinMath-1.5.2

来源：<https://github.com/Koishi-Satori/EirinMath> 的 **v1.5.2** release 源码包
（`refs/tags/v1.5.2.tar.gz`，该 release 没有二进制资产，只有 tarball）。

```
EirinMath-1.5.2/include/eirin/    <-- satfix 的 EIRIN_INC 指向这里
```

更新方式：

```bash
tools/fetch_eirin.sh           # 拉最新 release
tools/fetch_eirin.sh 1.5.3     # 拉指定版本
tools/fetch_eirin.sh --list    # 看有哪些版本
```

`build.sh` 的选择优先级：`EIRIN_INC` 环境变量 > `third_party/*/include` > 本地开发仓库
`/home/koishi/CLionProjects/fixed32`。所以拉了新版本后直接 `./build.sh` 就会用新的；
想临时切回本地仓库就 `EIRIN_INC=/home/koishi/CLionProjects/fixed32/include ./build.sh`。

### 与本地开发仓库的关系

本地 `~/CLionProjects/fixed32` 是同一个库的开发副本（remote 曾用名 `EirinFixed`，
现在/将来以 EirinMath 为准），当前在 `v1.5.2-8-gb82581d`，比这份 release 多 8 个提交。
satfix 需要的接口（`fixed_num`、`saturating_add/sub/mul/div`、`saturating_cast`）
在 1.5.2 release 里已经齐备，两份都能编译通过并同样跑过对拍测试。

要用本地那份的新接口，把 `EIRIN_INC` 指过去即可，不需要改代码：

```bash
EIRIN_INC=~/CLionProjects/fixed32/include ./build.sh
```
