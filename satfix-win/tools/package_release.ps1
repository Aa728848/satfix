#!/usr/bin/env pwsh
# 打发布包：按手册 §10.1/§10.2 产出 zip + .sha256。
#
# 用法：
#   .\tools\package_release.ps1                 # 版本从 plugin\stl-plugin.json 读
#   .\tools\package_release.ps1 -OutDir ..\rel  # 指定输出目录
#
# 为什么单独一个脚本而不是塞进 build.ps1：
#   build.ps1 只管「编译 + 自测 + 组装 dist\satfix\」；发布涉及 tag 与版本号一致性，
#   是另一个动作。手册 §13 要求「标签 = v + version」，这个脚本把那个检查做在打包时，
#   免得打出一个和清单版本对不上的包。

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'release'),
    [string]$Exe    = 'D:\Steam\steamapps\common\Stellaris\stellaris.exe'
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Root = Split-Path -Parent $Here
$Dist = Join-Path $Root 'dist\satfix'

if (-not (Test-Path (Join-Path $Dist 'satfix.dll'))) {
    throw "没有找到 $Dist\satfix.dll —— 先跑 .\build.ps1 组装发布包。"
}

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

$name = "satfix-v$version"
$stage = Join-Path $OutDir "stage\$name"
New-Item -ItemType Directory -Force (Join-Path $stage 'defaults') | Out-Null
Copy-Item (Join-Path $Dist 'stl-plugin.json') $stage
Copy-Item (Join-Path $Dist 'satfix.dll') $stage
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
Write-Host "    gh release create v$version `"$name.zip`" `"$name.zip.sha256`" --title `"satfix v$version`" --notes `"...`""
