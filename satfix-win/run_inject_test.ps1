# 起游戏 + 注入 satfix.dll + 读日志（活体探针模式）
# 用法: pwsh -NoProfile -File run_inject_test.ps1 [-Wait 20]
param([int]$Wait = 20, [switch]$KeepGame)
$ErrorActionPreference = 'Stop'
$H = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $H 'plugin\logs\satfix.log'
$stl = "$env:LOCALAPPDATA\Programs\Stellaris Launcher\stl.exe"
$exe = 'D:\Steam\steamapps\common\Stellaris\stellaris.exe'

# 确保没有残留
Get-Process stellaris -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
Start-Sleep -Seconds 3
Remove-Item $log -Force -ErrorAction SilentlyContinue

$env:SATFIX_WIN_FORCE = '1'
Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe)
Start-Sleep -Seconds 9
& $stl inject (Join-Path $H 'plugin\satfix.dll') 2>&1 | Select-Object -First 2
Start-Sleep -Seconds $Wait
Remove-Item Env:\SATFIX_WIN_FORCE -ErrorAction SilentlyContinue

Write-Host "`n=== 存活 ==="
Get-Process stellaris -ErrorAction SilentlyContinue |
    Select-Object Id,@{n='MB';e={[int]($_.WorkingSet64/1MB)}} | Format-Table -AutoSize

Write-Host "=== 安装 / 自检 / 探针 / EVENT ==="
Select-String -Path $log -Pattern '判定逻辑自检：|共装上|签名校验通过|跳过 |探针 |EVENT |首次调用|hooked ' |
    ForEach-Object { $_.Line }

if (-not $KeepGame) {
    Write-Host "`n=== 关游戏 ==="
    Get-Process stellaris -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
    Start-Sleep -Seconds 4
}
