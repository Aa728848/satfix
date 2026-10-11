# 测帧率：用 GetWindowRect 轮询游戏窗口是否响应 + 进程 CPU 占用，
# 再抓一帧画面。用来给「卡不卡」一个可比较的数字。
param([int]$Seconds = 20)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class P {
  [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
}
'@
$p = Get-Process stellaris -ErrorAction SilentlyContinue
if (-not $p) { Write-Host 'no game'; exit 1 }
$h = $p.MainWindowHandle
$c0 = $p.CPU
$sw = [Diagnostics.Stopwatch]::StartNew()
$hung = 0; $samples = 0
while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
    $samples++
    if ([P]::IsHungAppWindow($h)) { $hung++ }
    Start-Sleep -Milliseconds 200
}
$sw.Stop()
$p2 = Get-Process stellaris -ErrorAction SilentlyContinue
$cpu = $p2.CPU - $c0
Write-Host ("采样={0}  挂起={1}  CPU秒={2:N2}  窗口CPU占比={3:N1}%" -f $samples, $hung, $cpu, (100*$cpu/$sw.Elapsed.TotalSeconds))
Write-Host ("内存={0:N0}MB  线程={1}" -f ($p2.WorkingSet64/1MB), $p2.Threads.Count)
