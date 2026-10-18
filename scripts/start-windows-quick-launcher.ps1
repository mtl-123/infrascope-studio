[CmdletBinding()]
param(
    [string]$Platform = 'https://127.0.0.1:18443',
    [ValidateRange(1,65535)][int]$Port = 4173,
    [string]$Hotkey = 'Ctrl+Alt+Space'
)
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'InfraScope')).TrimEnd('\')
$runtime = [IO.Path]::GetFullPath((Join-Path $base 'runtime\windows-connector\launcher'))
if (-not $runtime.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid runtime path' }
foreach ($directory in @($base, (Split-Path -Parent $runtime), $runtime)) {
    if (Test-Path -LiteralPath $directory) {
        if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing runtime reparse point' }
    } else { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
}
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-connector\launcher\quick-launcher.ps1'
$target = Join-Path $runtime 'quick-launcher.ps1'
$state = Join-Path $base 'runtime\quick-launcher.process.json'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path -LiteralPath $state) {
    $prior = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
    $process = Get-Process -Id ([int]$prior.pid) -ErrorAction SilentlyContinue
    if ($process) {
        $native = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)"
        if ($native.ExecutablePath -ne $powershell -or $native.CommandLine -notlike ('*"' + $target + '"*') -or $process.StartTime.ToUniversalTime().ToString('o') -ne $prior.startedAt) { throw 'Stored PID is not this launcher; no process was stopped' }
        if ($prior.platform -ne $Platform -or $prior.hotkey -ne $Hotkey -or [int]$prior.port -ne $Port) { throw 'Existing launcher has other settings; exit it from the tray before restarting' }
        [pscustomobject]@{ok=$true;reused=$true;pid=$process.Id;hotkey=$Hotkey} | ConvertTo-Json -Compress
        return
    }
}
Copy-Item -LiteralPath $source -Destination $target -Force
$logs = Join-Path $base 'runtime\logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$stdout = Join-Path $logs "quick-launcher-$stamp.stdout.log"
$stderr = Join-Path $logs "quick-launcher-$stamp.stderr.log"
$arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "{0}" -ConnectorOrigin "http://127.0.0.1:{1}" -PlatformOrigin "{2}" -Hotkey "{3}"' -f $target,$Port,$Platform,$Hotkey
if ($Platform -notmatch '^https://(127\.0\.0\.1|localhost):[0-9]+$' -or $Hotkey -notmatch '^[A-Za-z0-9+]+$') { throw 'Starter accepts only local HTTPS and a simple hotkey chord' }
$child = Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
Start-Sleep -Seconds 2
$child.Refresh()
if ($child.HasExited) { throw "Launcher exited; inspect $stderr" }
$saved = [pscustomobject]@{pid=$child.Id;startedAt=$child.StartTime.ToUniversalTime().ToString('o');platform=$Platform;hotkey=$Hotkey;port=$Port;script=$target;stderr=$stderr;stdout=$stdout}
$saved | ConvertTo-Json | Set-Content -LiteralPath $state -Encoding UTF8
[pscustomobject]@{ok=$true;reused=$false;pid=$child.Id;hotkey=$Hotkey;stderr=$stderr;boundary='Process running; physical hotkey and real remote login remain to verify'} | ConvertTo-Json -Compress
