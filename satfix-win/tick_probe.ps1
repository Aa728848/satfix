# 测「游戏时间推进速度」：从日志的 SAMPLE 时间戳推断不行，
# 改用游戏自己写的 pdx_settings 无时间戳 —— 所以直接测**模拟线程的 CPU 时间**：
# 过一天变慢 = 同样的游戏内时间消耗更多 CPU。这里给一个可比较的基线数字。
#
# 更好的指标：hook 总调用数（g_calls）。我们用日志的心跳行（heartbeat_every）
# 来数单位时间内处理了多少次调用 —— 数字越低说明单次越慢。
param([int]$Seconds = 30, [string]$Tag = 'A')
$ErrorActionPreference = 'Stop'
$p = Get-Process stellaris -ErrorAction SilentlyContinue
if (-not $p) { Write-Host 'no game'; exit 1 }

$lg = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'plugin\logs\satfix.log'
function LogLines { if (Test-Path $lg) { (Get-Content $lg -ErrorAction SilentlyContinue).Count } else { 0 } }

$c0 = $p.CPU
$l0 = LogLines
$sw = [Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $Seconds
$sw.Stop()
$p2 = Get-Process stellaris -ErrorAction SilentlyContinue
$cpu = $p2.CPU - $c0
$l1 = LogLines

Write-Host ("[$Tag] {0:N0}s  CPU={1:N2}s ({2:N1}%)  内存={3:N0}MB  日志行={4}->{5}" -f `
        $sw.Elapsed.TotalSeconds, $cpu, (100*$cpu/$sw.Elapsed.TotalSeconds), `
        ($p2.WorkingSet64/1MB), $l0, $l1)
