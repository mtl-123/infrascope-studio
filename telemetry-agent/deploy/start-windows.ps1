param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('host', 'docker', 'pve')]
    [string]$Kind,
    [Parameter(Mandatory = $true)]
    [string]$Config,
    [ValidateSet('run', 'once', 'sample', 'status', 'enroll')]
    [string]$Command = 'run'
)

$ErrorActionPreference = 'Stop'
$binaries = @{
    host = 'infrascope-agent.exe'
    docker = 'infrascope-docker-collector.exe'
    pve = 'infrascope-pve-collector.exe'
}
$resolvedConfig = (Resolve-Path -LiteralPath $Config).ProviderPath
if (-not (Test-Path -LiteralPath $resolvedConfig -PathType Leaf)) {
    throw 'Configuration must be an existing file.'
}
$root = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $root $binaries[$Kind]
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    $binary = Join-Path (Join-Path $root 'bin') $binaries[$Kind]
}
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Binary missing: place this deployment directory beside the release binaries.'
}
if ($Command -eq 'enroll' -and [string]::IsNullOrWhiteSpace($env:INFRASCOPE_ENROLLMENT_TOKEN)) {
    throw 'Set INFRASCOPE_ENROLLMENT_TOKEN in this process environment before enrollment. Never pass the token as an argument.'
}
# Keep the same Windows account used for enrollment: DPAPI protects its key.
& $binary $Command --config $resolvedConfig
exit $LASTEXITCODE
