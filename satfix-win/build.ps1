# ===========================================================================
#  构建 satfix-win（Windows/x64, MSVC）
#
#  用法:
#      .\build.ps1                影子模式（默认；只观测，绝不改数值）
#      .\build.ps1 -Replace       打开"检出问题时回写饱和值"
#      .\build.ps1 -TestOnly      只编译并运行 winhook 自测
#
#  为什么不用 CMake：本机只装了 VS Build Tools（无 cmake/ninja），
#  vcvars64.bat + cl 是依赖最少的路径。CMakeLists.txt 也提供了。
# ===========================================================================
[CmdletBinding()]
param(
    [switch]$Replace,
    [switch]$TestOnly
)

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out  = Join-Path $Here 'build'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path $Out | Out-Null }

# ---- 找并进入 vcvars64 环境 ------------------------------------------------
function Get-VcVars {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) { return $null }  # 已在开发者命令行
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw "找不到 vswhere.exe，也找不到 cl.exe。请安装 VS Build Tools。" }
    $path = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if (-not $path) { throw "vswhere 找不到带 x64 C++ 工具链的 VS 安装。" }
    $vc = Join-Path $path 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vc)) { throw "找不到 $vc" }
    Write-Host "[build] 工具链: $path"
    return $vc
}

$vcvars = Get-VcVars

# 在 vcvars 环境里跑 cl：把命令交给 cmd 一次性执行，环境变量才不会丢
function Invoke-Cl {
    param([string[]]$ClArgs, [string]$What)
    Write-Host "[build] $What"
    $inner = 'call "{0}" >nul && cl.exe {1}' -f $vcvars, ($ClArgs -join ' ')
    if (-not $vcvars) { $inner = 'cl.exe ' + ($ClArgs -join ' ') }
    & cmd.exe /c $inner
    if ($LASTEXITCODE -ne 0) { throw "$What 失败（exit $LASTEXITCODE）" }
}

$common = @('/nologo', '/std:c++20', '/MT', '/O2', '/W4', '/EHsc', '/utf-8', "-I`"$Here`"")

# ---- 自测 ------------------------------------------------------------------
Invoke-Cl -What '编译 winhook 自测' -ClArgs ($common + @(
    "/Fo`"$Out\\`"", "/Fe`"$Out\test_winhook.exe`"", "`"$Here\test\test_winhook.cpp`""
))

Write-Host '[build] 运行 winhook 自测'
& (Join-Path $Out 'test_winhook.exe')
if ($LASTEXITCODE -ne 0) {
    throw 'hook 引擎自测失败 —— 先修好这个，别进游戏'
}

if ($TestOnly) { Write-Host '[build] -TestOnly：到此为止。'; return }

# ---- 离线对拍 --------------------------------------------------------------
Invoke-Cl -What '编译定点算术离线对拍' -ClArgs ($common + @(
    "/Fo`"$Out\\`"", "/Fe`"$Out\test_stl_fix_win.exe`"", "`"$Here\test\test_stl_fix_win.cpp`""
))

Write-Host '[build] 运行离线对拍'
& (Join-Path $Out 'test_stl_fix_win.exe')
if ($LASTEXITCODE -ne 0) { throw '定点对拍失败，别往下走' }

# ---- 插件 DLL --------------------------------------------------------------
$replaceVal = if ($Replace) { 1 } else { 0 }

# 版本号从清单读，编译期注入 —— 避免源码里硬编码版本号后与清单脱节
# （发布说明、tag、清单 version 三者必须一致，让源码成为第 4 个手工同步点太脆）。
$manifest = Get-Content (Join-Path $Here 'plugin\stl-plugin.json') -Raw | ConvertFrom-Json
$pluginVersion = $manifest.version
if (-not $pluginVersion) { throw 'plugin\stl-plugin.json 里没有 version' }
Write-Host "[build] 清单版本：$pluginVersion"

Invoke-Cl -What "编译插件 DLL（SATFIX_REPLACE=$replaceVal）" -ClArgs ($common + @(
    "/DSATFIX_REPLACE=$replaceVal",
    "/DSATFIX_VERSION=$pluginVersion",    '/DUNICODE', '/D_UNICODE', '/DWIN32_LEAN_AND_MEAN', '/DNOMINMAX',
    "/Fo`"$Out\\`"", "/Fe`"$Out\satfix.dll`"",
    '/LD', "`"$Here\src\sat_guard_win.cpp`"", '/link', '/INCREMENTAL:NO'
))

Write-Host "[build] 完成。产物：$Out\satfix.dll"

# ---- 插件管线自测（宿主侧 LoadLibrary）---------------------------------------
Invoke-Cl -What '编译插件管线自测' -ClArgs ($common + @(
    "/Fo`"$Out\\`"", "/Fe`"$Out\test_load_plugin.exe`"", "`"$Here\test\test_load_plugin.cpp`""
))

Write-Host '[build] 运行插件管线自测（在本进程里 LoadLibrary satfix.dll）'
# SATFIX_WIN_FORCE=1 让插件跳过"必须是 stellaris.exe"的检查，
# 这样才验证得到日志/目录/导出一致性；构建时间戳检查依然会（正确地）失败。
$env:SATFIX_WIN_FORCE = '1'
& (Join-Path $Out 'test_load_plugin.exe') (Join-Path $Out 'satfix.dll')
$pipelineRc = $LASTEXITCODE
Remove-Item Env:\SATFIX_WIN_FORCE -ErrorAction SilentlyContinue
if ($pipelineRc -ne 0) { throw '插件管线自测失败' }

Write-Host "[build] 全部通过。插件包见 $Here\plugin"

# ---- 组装插件包（手册第 3 节的目录约定）-------------------------------------
#
# 两个目录，用途不同，别混：
#
#   plugin\        开发/链接用的插件文件夹。stl plugin install --link 指向它，
#                  所以运行时启动器会在这里生成 config\、插件会写 logs\ ——
#                  **这是对的**（手册第 3 节：config\ 与 logs\ 属于用户）。
#                  不要拿它做发布前检查，它一定含 config\/logs\。
#
#   dist\satfix\   **发布包**：只有清单 + DLL + defaults\。
#                  手册 10.1：发布包必须不包含 config\、logs\。
#                  包合规检查查的是这个。
$pkg = Join-Path $Here 'plugin'
Copy-Item (Join-Path $Out 'satfix.dll') (Join-Path $pkg 'satfix.dll') -Force
Write-Host '[build] 已把 satfix.dll 复制进链接用的 plugin\'

$dist = Join-Path $Here 'dist\satfix'
if (Test-Path $dist) {
    # 只删这个发布目录里的具体文件，不做递归删除
    Get-ChildItem -Path $dist -File -Recurse | Remove-Item -Force
} else {
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
}
New-Item -ItemType Directory -Path (Join-Path $dist 'defaults') -Force | Out-Null
Copy-Item (Join-Path $pkg 'stl-plugin.json') $dist -Force
Copy-Item (Join-Path $Out 'satfix.dll') $dist -Force
Copy-Item (Join-Path $pkg 'defaults\satfix.ini') (Join-Path $dist 'defaults') -Force
Write-Host "[build] 发布包已组装: $dist"

# ---- 插件包合规检查（手册第 13 节）-----------------------------------------
$check = Join-Path $Here 'tools\check_plugin_pkg.py'
if (Get-Command python -ErrorAction SilentlyContinue) {
    & python $check $dist --exe 'D:\Steam\steamapps\common\Stellaris\stellaris.exe'
    if ($LASTEXITCODE -ne 0) { throw '发布包不合规（见上面 FAIL 项）' }
} else {
    Write-Host '[build] 没有 python，跳过插件包检查'
}

Write-Host ''
Write-Host '[build] 安装与启动：'
Write-Host "    stl plugin install `"$pkg`" --link     # 开发时用链接（config\ 与 logs\ 会写在它里面，正常）"
Write-Host '    stl plugin enable satfix'
Write-Host '    stl launch'
Write-Host "    # 日志： $pkg\logs\satfix.log"
Write-Host "    # 发布用的 zip 打 $dist 里的内容（不含 config\/logs\）"
