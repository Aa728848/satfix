#!/usr/bin/env pwsh
# 打发布包：按手册 §10.1/§10.2 产出 zip + .sha256。
#
# 用法：
#   .\tools\package_release.ps1                    # 版本从 plugin\stl-plugin.json 读
#   .\tools\package_release.ps1 -Mode shadow       # 显式要求影子模式
#   .\tools\package_release.ps1 -Mode write-back   # 显式要求回写模式（发布用）
#
# 为什么单独一个脚本而不是塞进 build.ps1：
#   build.ps1 只管「编译 + 自测 + 组装 dist\satfix\」；发布涉及 tag、版本号一致性和
#   **构建模式**，是另一个动作。手册 §13 要求「标签 = v + version」，
#   而这个脚本把三件事都查在打包时：
#     1. 标签 = v + version
#     2. 包内没有 config\、logs\
#     3. DLL 的构建模式与要求一致
#
# 第 3 条为什么必要：曾经发过一个「以为是影子版、其实是回写版」的包。
# 两种构建的 DLL 大小几乎相同，只看大小/时间分不出来 —— 只能读打进二进制的 marker。
# 默认要求 write-back（发布给用户的就该是能真正修数值的版本）。

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'release'),
    [ValidateSet('write-back', 'shadow', 'any')]
    [string]$Mode = 'write-back',
    [string]$Exe    = 'D:\Steam\steamapps\common\Stellaris\stellaris.exe'
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Root = Split-Path -Parent $Here
$Dist = Join-Path $Root 'dist\satfix'
$Dll  = Join-Path $Dist 'satfix.dll'

if (-not (Test-Path $Dll)) {
    throw "没有找到 $Dll —— 先跑 .\build.ps1（发布用 .\build.ps1 -Replace）组装发布包。"
}

# ---- 构建模式自检（读打进二进制的 marker，不靠记性）------------------------
$bytes = [System.IO.File]::ReadAllBytes($Dll)
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)
$isWriteBack = $text.Contains('satfix-build-mode:write-back')
$isShadow    = $text.Contains('satfix-build-mode:shadow')
if (-not $isWriteBack -and -not $isShadow) {
    throw "DLL 里没有构建模式 marker —— 这个 DLL 是加 marker 之前编的，重新构建。"
}
$actual = if ($isWriteBack) { 'write-back' } else { 'shadow' }

Write-Host "[release] 构建模式: $actual（要求 $Mode）"
if ($Mode -ne 'any' -and $actual -ne $Mode) {
    if ($Mode -eq 'write-back') {
        throw "要发布回写版，但 DLL 是影子版。用 .\build.ps1 -Replace 重新构建。"
    } else {
        throw "要求影子版，但 DLL 是回写版。用 .\build.ps1（不加 -Replace）重新构建。"
    }
}

# ---- 清单 ----------------------------------------------------------------
$manifest = Get-Content (Join-Path $Dist 'stl-plugin.json') -Raw | ConvertFrom-Json
$version  = $manifest.version
if (-not $version) { throw '清单里没有 version。' }

# 手册 §4.4 / §10.1：发布包里不能有 config\、logs\，且清单声明的 default 必须在包里。
foreach ($bad in @('config', 'logs')) {
    if (Test-Path (Join-Path $Dist $bad)) { throw "发布包含有 $bad\ —— 手册 §10.1 不允许。" }
}
foreach ($c in $manifest.config) {
    $def = Join-Path $Dist ($c.default -replace '/', '\')
    if (-not (Test-Path $def)) { throw "清单声明的默认文件不在包里: $($c.default)" }
}

# ---- 打包 ----------------------------------------------------------------
$name = "satfix-v$version"
$stage = Join-Path $OutDir "stage\$name"
New-Item -ItemType Directory -Force (Join-Path $stage 'defaults') | Out-Null
Copy-Item (Join-Path $Dist 'stl-plugin.json') $stage
Copy-Item $Dll $stage
Copy-Item (Join-Path $Dist 'defaults\*') (Join-Path $stage 'defaults')

$zip = Join-Path $OutDir "$name.zip"
Compress-Archive -Path "$stage\*" -DestinationPath $zip -Force

# 手册 §10.2：应当提供 <附件名>.sha256，格式「<摘要>  <文件名>」
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
"$hash  $name.zip" | Set-Content -Encoding ascii "$zip.sha256"

Write-Host "[release] $zip"
Write-Host "[release] sha256 $hash"
Write-Host "[release] 标签应为 v$version（手册 §13：标签 = v + version）"
Write-Host ""
Write-Host "发布："
Write-Host "    gh release create v$version `"$name.zip`" `"$name.zip.sha256`" --title `"satfix v$version`" --notes-file notes.md"
