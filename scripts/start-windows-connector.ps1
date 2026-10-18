[CmdletBinding()]
param(
    [string]$NodePath = (Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'),
    [string]$Platform = 'https://127.0.0.1:18443',
    [string]$CertificatePath = (Join-Path $env:LOCALAPPDATA 'InfraScope\local-platform\server.crt'),
    [ValidateRange(1, 65535)][int]$Port = 4173,
    [string]$SourceRoot = ''
)
$ErrorActionPreference = 'Stop'
if (-not $SourceRoot) { $SourceRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-connector' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script in the interactive Windows user session, not inside WSL.'
}
if (-not [Environment]::UserInteractive) { throw 'An interactive Windows user session is required.' }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is required.' }

$origin = [Uri]$Platform
if (-not $origin.IsAbsoluteUri -or $origin.Scheme -ne 'https' -or $origin.UserInfo -or
    $origin.AbsolutePath -ne '/' -or $origin.Query -or $origin.Fragment) {
    throw 'Platform must be an exact HTTPS origin without credentials, path, query or fragment.'
}
$Platform = $origin.GetLeftPart([UriPartial]::Authority)
$node = (Get-Item -LiteralPath $NodePath -ErrorAction Stop).FullName
$cert = (Get-Item -LiteralPath $CertificatePath -ErrorAction Stop).FullName
if (-not (Test-Path -LiteralPath $node -PathType Leaf) -or [IO.Path]::GetExtension($node) -ne '.exe') {
    throw 'NodePath must identify a Windows node.exe file.'
}
if (-not (Test-Path -LiteralPath $cert -PathType Leaf) -or
    -not (Get-Content -LiteralPath $cert -Raw).Contains('-----BEGIN CERTIFICATE-----')) {
    throw 'CertificatePath must identify the trusted local platform public PEM certificate.'
}
$nodeVersion = & $node --version
if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v(\d+)\.' -or [int]$Matches[1] -lt 22) {
    throw 'A working Windows Node.js 22 or later is required.'
}
$source = (Get-Item -LiteralPath $SourceRoot -ErrorAction Stop).FullName.TrimEnd('\')
$base = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'InfraScope')).TrimEnd('\')

function Assert-ManagedPath([string]$Value) {
    $full = [IO.Path]::GetFullPath($Value)
    if ($full -ne $base -and -not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runtime path is outside the intended InfraScope directory.'
    }
    # Refuse junctions/symlinks so a safe-looking path cannot redirect a write.
    $current = $full
    while ($current -eq $base -or $current.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a reparse point in the runtime path: $current"
            }
        }
        if ($current -eq $base) { break }
        $current = Split-Path -Parent $current
    }
    return $full
}
function Ensure-ManagedDirectory([string]$Value) {
    $full = Assert-ManagedPath $Value
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
    return $full
}
function Get-Listeners {
    return @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq $Port })
}
function Confirm-LocalStatus([int]$ExpectedPID) {
    $listeners = @(Get-Listeners)
    if ($listeners.Count -ne 1 -or $listeners[0].OwningProcess -ne $ExpectedPID -or
        $listeners[0].LocalAddress -ne '127.0.0.1') { return $false }
    $url = "http://127.0.0.1:$Port"
    try {
        $token = Invoke-RestMethod -Uri "$url/api/local-token" -TimeoutSec 2
        if (-not $token.available -or $token.mode -ne 'controlled' -or -not $token.token) { return $false }
        $status = Invoke-RestMethod -Uri "$url/api/status" -Headers @{ 'X-Pulse-Token' = $token.token } -TimeoutSec 2
        return $status.mode -eq 'controlled' -and $status.platform -eq $Platform -and $status.identity.interactive
    } catch { return $false }
}

$runtime = Assert-ManagedPath (Join-Path $base 'runtime\windows-connector')
$logs = Assert-ManagedPath (Join-Path $base 'runtime\logs')
$statePath = Assert-ManagedPath (Join-Path $base "runtime\connector-$Port.process.json")
$server = Assert-ManagedPath (Join-Path $runtime 'server.mjs')
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$mutex = New-Object Threading.Mutex($false, "Local\InfraScope-Connector-Starter-$sid-$Port")
$locked = $false
try {
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another connector start operation is in progress.' }
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $saved = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $running = Get-Process -Id ([int]$saved.pid) -ErrorAction SilentlyContinue
        if ($running) {
            $native = Get-CimInstance Win32_Process -Filter "ProcessId = $($running.Id)" -ErrorAction Stop
            $commandPattern = '^(?:"' + [Regex]::Escape($node) + '"|' + [Regex]::Escape($node) +
                ')\s+(?:"' + [Regex]::Escape($server) + '"|' + [Regex]::Escape($server) + ')\s*$'
            if ($saved.nodePath -ne $node -or $saved.serverPath -ne $server -or
                $saved.startedAt -ne $running.StartTime.ToUniversalTime().ToString('o') -or
                $native.ExecutablePath -ne $node -or $native.CommandLine -notmatch $commandPattern) {
                throw 'The saved PID does not match this connector process; no process was stopped.'
            }
            if ($saved.platform -ne $Platform -or $saved.certificatePath -ne $cert -or [int]$saved.port -ne $Port) {
                throw 'The owned connector is running with other settings. Stop it explicitly before changing settings.'
            }
            if (-not (Confirm-LocalStatus $running.Id)) {
                throw 'The owned connector is running but not healthy; inspect its logs before restarting.'
            }
            [pscustomobject]@{ ok = $true; reused = $true; pid = $running.Id; url = "http://127.0.0.1:$Port";
                platform = $Platform; stdout = $saved.stdout; stderr = $saved.stderr; processState = $statePath } | ConvertTo-Json -Compress
            return
        }
    }
    if (@(Get-Listeners).Count) { throw "Port $Port is already occupied; no existing process was stopped." }

    $runtime = Ensure-ManagedDirectory $runtime
    $logs = Ensure-ManagedDirectory $logs
    $files = @('server.mjs', 'protocol.mjs', 'package.json', 'public\app.js', 'public\index.html',
        'public\styles.css', 'launcher\device-secrets.ps1', 'launcher\launch-rdp.ps1', 'launcher\setup-rdp-signing.ps1')
    foreach ($relative in $files) {
        $from = (Get-Item -LiteralPath (Join-Path $source $relative) -ErrorAction Stop).FullName
        if (-not $from.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $from -PathType Leaf)) { throw 'Invalid connector source file.' }
        $to = Assert-ManagedPath (Join-Path $runtime $relative)
        Ensure-ManagedDirectory (Split-Path -Parent $to) | Out-Null
        Copy-Item -LiteralPath $from -Destination $to -Force
    }

    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff')
    $stdout = Assert-ManagedPath (Join-Path $logs "connector-$Port-$stamp.stdout.log")
    $stderr = Assert-ManagedPath (Join-Path $logs "connector-$Port-$stamp.stderr.log")
    $variables = @{ INFRASCOPE_PLATFORM = $Platform; INFRASCOPE_MODE = 'controlled'; NODE_EXTRA_CA_CERTS = $cert;
        NODE_TLS_REJECT_UNAUTHORIZED = '1'; PORT = [string]$Port }
    $previous = @{}
    # Child-only configuration; never disable TLS validation or change user/machine environment.
    try {
        foreach ($name in $variables.Keys) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $variables[$name], 'Process')
        }
        $child = Start-Process -FilePath $node -ArgumentList ('"' + $server + '"') -WorkingDirectory $runtime -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    } finally {
        foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    }
    $record = [pscustomobject]@{ pid = $child.Id; nodePath = $node; serverPath = $server;
        startedAt = $child.StartTime.ToUniversalTime().ToString('o'); platform = $Platform; certificatePath = $cert;
        port = $Port; stdout = $stdout; stderr = $stderr }
    $record | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    $ready = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if ($child.HasExited) { throw "Connector exited with code $($child.ExitCode). Inspect $stderr" }
        if (Confirm-LocalStatus $child.Id) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
        $child.Refresh()
    }
    if (-not $ready) { throw "Connector did not become ready. No process was stopped. Inspect $stderr" }
    [pscustomobject]@{ ok = $true; reused = $false; pid = $child.Id; url = "http://127.0.0.1:$Port";
        platform = $Platform; stdout = $stdout; stderr = $stderr; processState = $statePath } | ConvertTo-Json -Compress
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
