[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$launcher = Join-Path (Split-Path -Parent $PSScriptRoot) 'launcher\quick-launcher.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ('Quick launcher parse failed: ' + ($errors.Message -join '; ')) }
foreach ($name in @('Get-LauncherOrigin', 'Get-LauncherHotkey', 'Get-LauncherText', 'Get-LauncherQuery', 'Get-LauncherCatalog', 'Get-LauncherBrowserUrl', 'Test-LauncherSearch')) {
    $definitions = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
    if ($definitions.Count -ne 1) { throw "Missing or duplicate helper: $name" }
    . ([ScriptBlock]::Create($definitions[0].Extent.Text))
}
$script:checks = 0
function Assert-True([bool]$Value, [string]$Name) {
    if (-not $Value) { throw "FAILED: $Name" }
    $script:checks++
}
function Assert-Rejected([scriptblock]$Action, [string]$Name) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-True $rejected $Name
}
$origin = 'https://127.0.0.1:18443'
Assert-True ((Get-LauncherOrigin 'http://127.0.0.1:4173/' -Connector) -eq 'http://127.0.0.1:4173') 'canonical loopback origin'
foreach ($bad in @('http://localhost:4173', 'http://127.0.0.1:4173/path', 'https://127.0.0.1:4173', 'http://user@127.0.0.1:4173', 'http://example.com:4173', 'http://127.0.0.1:4173/?x=1')) {
    Assert-Rejected { Get-LauncherOrigin $bad -Connector } 'reject nonliteral or ambiguous connector origin'
}
Assert-Rejected { Get-LauncherOrigin 'http://127.0.0.1:18443' } 'platform requires HTTPS'
$key = Get-LauncherHotkey 'Ctrl+Alt+Space'
Assert-True ($key.Modifiers -eq 0x4003 -and $key.VirtualKey -eq 32) 'default global hotkey and no-repeat'
Assert-True ((Get-LauncherHotkey 'Ctrl+Shift+F12').VirtualKey -eq 123) 'configurable hotkey'
foreach ($bad in @('Space', 'Ctrl+Ctrl+A', 'Ctrl+F25', 'Control+Alt+A', 'Ctrl+Alt+', 'Alt+Escape')) {
    Assert-Rejected { Get-LauncherHotkey $bad } 'reject invalid hotkey'
}
$item = [pscustomobject]@{ assetId = 'asset_1'; accountId = 'account-2'; assetName = 'Linux Build'; accountName = 'Deployment';
    username = 'deploy'; osFamily = 'linux'; protocol = 'ssh'; host = '10.20.30.40'; port = 22; password = 'unexpected-secret-field' }
$catalog = [pscustomobject]@{ items = @($item); platform = $origin; deviceName = 'test'; userId = 'user-3'; truncated = $false }
$safe = @(Get-LauncherCatalog $catalog $origin)
Assert-True ($safe.Count -eq 1 -and $safe[0].host -eq $item.host) 'catalog whitelist parses actual metadata'
Assert-True (-not ($safe[0].PSObject.Properties.Name -contains 'password')) 'unexpected credentials never retained'
Assert-True ($safe[0].userId -ceq 'user-3') 'paired identity retained for browser selection validation'
Assert-True (Test-LauncherSearch $safe[0] 'linux DEPLOY ssh') 'search case insensitive AND terms'
Assert-True (Test-LauncherSearch $safe[0] '10.20.30') 'search IP prefix'
Assert-True (-not (Test-LauncherSearch $safe[0] 'linux rdp')) 'search protocol mismatch'
Assert-True (@(Get-LauncherCatalog ([pscustomobject]@{ items = @(); platform = $origin; userId = 'user-3'; truncated = $false }) $origin).Count -eq 0) 'empty catalog does not fall back to examples'
Assert-Rejected { Get-LauncherCatalog $catalog 'https://example.com' } 'reject mismatched paired platform'
Assert-Rejected { Get-LauncherCatalog ([pscustomobject]@{ items = @($item, $item); platform = $origin; userId = 'user-3'; truncated = $false }) $origin } 'reject duplicate connection'
Assert-Rejected { Get-LauncherCatalog ([pscustomobject]@{ items = @($item); platform = $origin; truncated = $false }) $origin } 'reject missing catalog user identity'
Assert-Rejected { Get-LauncherCatalog ([pscustomobject]@{ items = @($item); platform = $origin; userId = 'user&evil'; truncated = $false }) $origin } 'reject malformed catalog identity'
Assert-Rejected { Get-LauncherCatalog ([pscustomobject]@{ items = @($item) * 201; platform = $origin; userId = 'user-3'; truncated = $true }) $origin } 'reject oversized catalog beyond server limit'
Assert-True ((Get-LauncherQuery ('a' * 200)).Length -eq 200) 'search permits 200 ASCII bytes'
Assert-Rejected { Get-LauncherQuery ('a' * 201) } 'search rejects over 200 ASCII bytes'
Assert-True ((Get-LauncherQuery (([string][char]0x4e2d) * 66)).Length -eq 66) 'search permits multibyte query below byte limit'
Assert-Rejected { Get-LauncherQuery (([string][char]0x4e2d) * 67) } 'search limit counts UTF8 bytes not characters'
Assert-Rejected { Get-LauncherQuery "linux`nssh" } 'search rejects control characters'
foreach ($mutation in @(@{ field = 'port'; value = 0 }, @{ field = 'protocol'; value = 'exec' }, @{ field = 'host'; value = 'x/evil' }, @{ field = 'username'; value = "name`nspoof" }, @{ field = 'assetId'; value = 'x&password=y' })) {
    $copy = $item | ConvertTo-Json | ConvertFrom-Json
    $copy.($mutation.field) = $mutation.value
    Assert-Rejected { Get-LauncherCatalog ([pscustomobject]@{ items = @($copy); platform = $origin; userId = 'user-3'; truncated = $false }) $origin } 'reject malformed catalog field'
}
$url = $origin + '/remote-workspace.html?assetId=asset_1&accountId=account-2&protocol=ssh&userId=user-3'
Assert-True ((Get-LauncherBrowserUrl $url $origin $safe[0]) -eq $url) 'allow matching authorized workspace URL'
foreach ($bad in @(
    $url.Replace('https:', 'http:'), $url.Replace('127.0.0.1', 'evil.example'), $url.Replace('18443', '18444'),
    $url.Replace('/remote-workspace.html', '/other.html'), $url.Replace('https://', 'https://user@'),
    ($url + '#token=x'), ($url + '&password=x'), ($url + '&assetId=asset_1'),
    $url.Replace('asset_1', 'other'), $url.Replace('protocol=ssh', 'protocol=sftp'),
    $url.Replace('accountId=account-2&', ''), ($url + '&%74oken=x'),
    $url.Replace('userId=user-3', 'userId=other-user'), $url.Replace('&userId=user-3', ''), ($url + '&userId=user-3')
)) { Assert-Rejected { Get-LauncherBrowserUrl $bad $origin $safe[0] } 'reject unsafe or mismatched browser URL' }
$source = [IO.File]::ReadAllText($launcher)
Assert-True ($source.Contains('$request.AllowAutoRedirect = $false') -and $source.Contains('$request.Proxy = $null')) 'local tokens never redirected or proxied'
Assert-True ($source.Contains('$worker.BeginInvoke()')) 'network requests outside the WinForms UI thread'
Assert-True ($source.Contains('[Uri]::EscapeDataString($Query)') -and $source.Contains('$searchTimer.Interval = 250')) 'debounced encoded server-side search'
Assert-True ($source.Contains('$completed.Generation -ne $script:catalogGeneration')) 'late catalog responses cannot overwrite current search'
Assert-True ($source.Contains('userId = $Selection.userId') -and $source.Contains('$Selection.userId -cne $script:catalogUserId')) 'open requires selected catalog owner and sends identity for connector re-pair rejection'
Assert-True ($source.Contains('$hotkeyWindow.Dispose()') -and $source.Contains('$mutex.ReleaseMutex()')) 'hotkey and mutex cleanup'
Assert-True (-not ($source -match '(?i)CredRead|CredWrite|postgres|password\s*=|Set-ItemProperty|Register-ScheduledTask')) 'no database password credential store or autostart operations'
[pscustomobject]@{ ok = $true; checks = $script:checks; mode = 'unit-helpers'; networkCalls = 0;
    remoteLaunches = 0; hotkeyPhysicallyPressed = $false } | ConvertTo-Json -Compress
