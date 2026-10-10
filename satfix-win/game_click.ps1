# 把游戏窗口提到前台（用 AttachThreadInput 绕过 Windows 的前台锁定），
# 截图确认位置，然后点一个按钮。
# 用法: pwsh -NoProfile -File game_click.ps1 -ClickX 741 -ClickY 1010
param([int]$ClickX = 0, [int]$ClickY = 0, [switch]$NoClick, [string]$Shot = 'game_shot.png')

$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class FG {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
'@

$p = Get-Process stellaris -ErrorAction SilentlyContinue
if (-not $p) { Write-Host 'no game'; exit 1 }
$h = $p.MainWindowHandle

$fg = [FG]::GetForegroundWindow()
$fgThread = [FG]::GetWindowThreadProcessId($fg, [IntPtr]::Zero)
$myThread = [FG]::GetCurrentThreadId()
$gameThread = [FG]::GetWindowThreadProcessId($h, [IntPtr]::Zero)
Write-Host "前台=$fg  我方线程=$myThread  前台线程=$fgThread  游戏线程=$gameThread"

# 附加到前台线程的输入队列 -> 就能合法设置前台窗口
[FG]::AttachThreadInput($myThread, $fgThread, $true) | Out-Null
[FG]::AttachThreadInput($myThread, $gameThread, $true) | Out-Null
[FG]::ShowWindow($h, 9) | Out-Null   # SW_RESTORE
[FG]::BringWindowToTop($h) | Out-Null
$ok = [FG]::SetForegroundWindow($h)
[FG]::AttachThreadInput($myThread, $gameThread, $false) | Out-Null
[FG]::AttachThreadInput($myThread, $fgThread, $false) | Out-Null
Start-Sleep -Milliseconds 1200
Write-Host "SetForegroundWindow=$ok  现在前台=$([FG]::GetForegroundWindow())  游戏=$h"

$r = New-Object FG+RECT
[FG]::GetWindowRect($h, [ref]$r) | Out-Null
Write-Host "窗口矩形 L=$($r.L) T=$($r.T) R=$($r.R) B=$($r.B)"

if (-not $NoClick -and $ClickX -gt 0) {
    [FG]::SetCursorPos($r.L + $ClickX, $r.T + $ClickY) | Out-Null
    Start-Sleep -Milliseconds 350
    [FG]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 90
    [FG]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Write-Host "已点击窗口内 ($ClickX,$ClickY)"
    Start-Sleep -Seconds 4
}

Add-Type -AssemblyName System.Drawing
$w = $r.R - $r.L; $ht = $r.B - $r.T
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size $w, $ht))
$out = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) $Shot
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "截图: $out"
