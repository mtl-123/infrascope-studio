[CmdletBinding()]
param(
    [string]$ConnectorOrigin = 'http://127.0.0.1:4173',
    [string]$PlatformOrigin = 'https://127.0.0.1:18443',
    [string]$Hotkey = 'Ctrl+Alt+Space',
    [switch]$SelfTest,
    [switch]$SmokeTest
)
$ErrorActionPreference = 'Stop'

function Get-LauncherOrigin([string]$Value, [switch]$Connector) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) {
        throw 'An origin without credentials, path, query or fragment is required.'
    }
    if ($Connector) {
        if ($uri.Scheme -ne 'http' -or $uri.Host -ne '127.0.0.1') {
            throw 'The connector must use the literal HTTP IPv4 loopback address.'
        }
    } elseif ($uri.Scheme -ne 'https') { throw 'The platform origin must use HTTPS.' }
    return $uri.GetLeftPart([UriPartial]::Authority)
}

function Get-LauncherHotkey([string]$Value) {
    $parts = @($Value -split '\+' | ForEach-Object { $_.Trim().ToUpperInvariant() })
    if ($parts.Count -lt 2) { throw 'A hotkey needs modifiers and a key, for example Ctrl+Alt+Space.' }
    $modifiers = 0x4000 # MOD_NOREPEAT prevents held keys reopening the window.
    $seen = @{}
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        $part = $parts[$i]
        if ($seen.ContainsKey($part)) { throw 'Duplicate hotkey modifier.' }
        $seen[$part] = $true
        switch ($part) {
            'ALT' { $modifiers = $modifiers -bor 1 }
            'CTRL' { $modifiers = $modifiers -bor 2 }
            'SHIFT' { $modifiers = $modifiers -bor 4 }
            'WIN' { $modifiers = $modifiers -bor 8 }
            default { throw 'Supported modifiers are Ctrl, Alt, Shift and Win.' }
        }
    }
    $key = $parts[-1]
    if ($key -eq 'SPACE') { $virtualKey = 32 }
    elseif ($key -match '^[A-Z0-9]$') { $virtualKey = [int][char]$key }
    elseif ($key -match '^F([1-9]|1[0-9]|2[0-4])$') { $virtualKey = 111 + [int]$Matches[1] }
    else { throw 'Supported hotkey keys are Space, A-Z, 0-9 and F1-F24.' }
    return [pscustomobject]@{ Modifiers = $modifiers; VirtualKey = $virtualKey; Label = $Value }
}

function Get-LauncherText($Value, [int]$Maximum = 256) {
    if ($Value -isnot [string] -or $Value.Length -gt $Maximum -or $Value -match '[\x00-\x1f\x7f]') {
        throw 'The connector returned invalid catalog text.'
    }
    return $Value
}

function Get-LauncherQuery([string]$Value) {
    if ([Text.Encoding]::UTF8.GetByteCount($Value) -gt 200 -or $Value -match '[\x00-\x1f\x7f]') {
        throw 'Search must be at most 200 UTF-8 bytes and contain no control characters.'
    }
    return $Value.Trim()
}

function Get-LauncherCatalog($Data, [string]$ExpectedPlatform) {
    if (-not $Data -or -not ($Data.PSObject.Properties.Name -contains 'items') -or $null -eq $Data.items -or
        $Data.items -isnot [System.Array] -or $Data.items.Count -gt 200 -or $Data.truncated -isnot [bool]) {
        throw 'The connector returned an invalid catalog.'
    }
    if ((Get-LauncherOrigin ([string]$Data.platform)) -cne $ExpectedPlatform) {
        throw 'The paired platform does not match the configured platform origin.'
    }
    $userId = Get-LauncherText $Data.userId 128
    if ($userId -notmatch '^[A-Za-z0-9_-]{1,128}$') { throw 'The catalog has no valid paired user identity.' }
    $seen = @{}
    foreach ($item in $Data.items) {
        $assetId = Get-LauncherText $item.assetId 128
        $accountId = Get-LauncherText $item.accountId 128
        if ($assetId -notmatch '^[A-Za-z0-9_-]{1,128}$' -or $accountId -notmatch '^[A-Za-z0-9_-]{1,128}$') {
            throw 'The connector returned an invalid connection identifier.'
        }
        $protocol = Get-LauncherText $item.protocol 8
        if ($protocol -cnotin @('ssh', 'sftp', 'rdp')) { throw 'The connector returned an unsupported protocol.' }
        if (($item.port -isnot [int] -and $item.port -isnot [long]) -or $item.port -lt 1 -or $item.port -gt 65535) {
            throw 'The connector returned an invalid connection port.'
        }
        $hostName = Get-LauncherText $item.host 255
        if (-not $hostName -or $hostName -match '[\s/\\@?#]') { throw 'The connector returned an invalid connection host.' }
        $key = $assetId + '/' + $accountId + '/' + $protocol
        if ($seen.ContainsKey($key)) { throw 'The connector returned duplicate connection records.' }
        $seen[$key] = $true
        # Whitelist display metadata: never retain credential or token fields from a response.
        [pscustomobject]@{
            assetId = $assetId; accountId = $accountId; protocol = $protocol; userId = $userId
            assetName = (Get-LauncherText $item.assetName); accountName = (Get-LauncherText $item.accountName)
            username = (Get-LauncherText $item.username 512); osFamily = (Get-LauncherText $item.osFamily 64)
            host = $hostName; port = [int]$item.port
        }
    }
}

function Get-LauncherBrowserUrl([string]$Value, [string]$ExpectedPlatform, $Selection) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or
        $uri.UserInfo -or $uri.Fragment -or $uri.GetLeftPart([UriPartial]::Authority) -cne $ExpectedPlatform -or
        $uri.AbsolutePath -cne '/remote-workspace.html') {
        throw 'The connector returned an untrusted workspace URL.'
    }
    $values = @{}
    foreach ($part in ($uri.Query.TrimStart('?') -split '&')) {
        $pair = $part -split '=', 2
        if ($pair.Count -ne 2) { throw 'The workspace URL has invalid parameters.' }
        $name = [Uri]::UnescapeDataString($pair[0])
        $value = [Uri]::UnescapeDataString($pair[1])
        if ($name -cnotin @('assetId', 'accountId', 'protocol', 'userId') -or $values.ContainsKey($name)) {
            throw 'The workspace URL contains unexpected parameters.'
        }
        $values[$name] = $value
    }
    if ($values.Count -ne 4 -or -not $Selection.userId -or $values.userId -cne $Selection.userId -or $values.assetId -cne $Selection.assetId -or
        $values.accountId -cne $Selection.accountId -or $values.protocol -cne $Selection.protocol -or
        $values.protocol -cnotin @('ssh', 'sftp')) {
        throw 'The workspace URL does not match the selected connection.'
    }
    return $uri.AbsoluteUri
}

function Test-LauncherSearch($Item, [string]$Query) {
    $text = ($Item.assetName, $Item.host, $Item.username, $Item.accountName, $Item.protocol, $Item.osFamily) -join ' '
    foreach ($word in @($Query.Trim() -split '\s+' | Where-Object { $_ })) {
        if ($text.IndexOf($word, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    }
    return $true
}

$ConnectorOrigin = Get-LauncherOrigin $ConnectorOrigin -Connector
$PlatformOrigin = Get-LauncherOrigin $PlatformOrigin
$hotkeyConfig = Get-LauncherHotkey $Hotkey
if ($SelfTest) {
    [pscustomobject]@{ ok = $true; connector = $ConnectorOrigin; platform = $PlatformOrigin;
        hotkey = $hotkeyConfig.Label; networkCalls = 0; credentialReads = 0; remoteLaunches = 0 } | ConvertTo-Json -Compress
    return
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run the quick launcher using Windows PowerShell 5.1.'
}
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA' -or -not [Environment]::UserInteractive) {
    throw 'An interactive STA Windows session is required. Start powershell.exe with -STA.'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Forms;
namespace InfraScope.QuickLauncher {
    public sealed class HotkeyWindow : NativeWindow, IDisposable {
        [DllImport("user32.dll", SetLastError=true)] static extern bool RegisterHotKey(IntPtr h, int id, uint modifiers, uint key);
        [DllImport("user32.dll", SetLastError=true)] static extern bool UnregisterHotKey(IntPtr h, int id);
        [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
        public event EventHandler Pressed;
        private bool registered;
        public HotkeyWindow(uint modifiers, uint key) {
            CreateHandle(new CreateParams());
            if (!RegisterHotKey(Handle, 1, modifiers, key)) {
                int error = Marshal.GetLastWin32Error();
                DestroyHandle();
                throw new Win32Exception(error, "The global hotkey is unavailable. Choose another -Hotkey; existing registrations are not changed.");
            }
            registered = true;
        }
        protected override void WndProc(ref Message m) {
            if (m.Msg == 0x0312 && m.WParam.ToInt32() == 1) {
                EventHandler handler = Pressed;
                if (handler != null) handler(this, EventArgs.Empty);
            }
            base.WndProc(ref m);
        }
        public void Dispose() {
            if (registered) { UnregisterHotKey(Handle, 1); registered = false; }
            if (Handle != IntPtr.Zero) DestroyHandle();
        }
    }
}
'@ -ReferencedAssemblies System.Windows.Forms, System.Drawing

# Run all network I/O outside the WinForms thread; never send the local token through a redirect or proxy.
$requestWorker = {
    param([string]$Origin, [string]$Operation, [string]$Body, [string]$Query)
    $ErrorActionPreference = 'Stop'
    function Request-LocalJSON([string]$Path, [string]$Method, [string]$Token, [string]$JSON) {
        $request = [Net.HttpWebRequest]::Create($Origin + $Path)
        $request.Method = $Method
        $request.AllowAutoRedirect = $false
        $request.Proxy = $null
        $request.Timeout = 12000
        $request.ReadWriteTimeout = 12000
        $request.KeepAlive = $false
        $request.Accept = 'application/json'
        if ($Token) { $request.Headers.Add('X-Pulse-Token', $Token) }
        if ($Method -eq 'POST') {
            $bytes = [Text.Encoding]::UTF8.GetBytes($JSON)
            $request.ContentType = 'application/json'
            $request.ContentLength = $bytes.Length
            $stream = $request.GetRequestStream()
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        }
        $response = $null
        try {
            $response = $request.GetResponse()
            if ([int]$response.StatusCode -ne 200) { throw 'The local connector did not return a successful response.' }
            if ($response.ContentType -notmatch '^application/json\b' -or $response.ContentLength -gt 2097152) {
                throw 'The local connector returned an invalid response.'
            }
            $reader = New-Object IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
            try {
                $buffer = New-Object char[] 4096
                $text = New-Object Text.StringBuilder
                while (($count = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($text.Length + $count -gt 2097152) { throw 'The local connector response is too large.' }
                    [void]$text.Append($buffer, 0, $count)
                }
                return ($text.ToString() | ConvertFrom-Json)
            } finally { $reader.Dispose() }
        } finally { if ($response) { $response.Dispose() } }
    }
    try {
        $authorization = Request-LocalJSON '/api/local-token' 'GET' '' ''
        if (-not $authorization.available -or $authorization.mode -ne 'controlled' -or
            $authorization.token -isnot [string] -or -not $authorization.token -or $authorization.token.Length -gt 1024) {
            throw 'The Windows connector must be running in controlled mode.'
        }
        if ($Operation -eq 'catalog') {
            $path = '/api/launcher/catalog?q=' + [Uri]::EscapeDataString($Query)
            $data = Request-LocalJSON $path 'GET' $authorization.token ''
        }
        elseif ($Operation -eq 'open') { $data = Request-LocalJSON '/api/launcher/open' 'POST' $authorization.token $Body }
        else { throw 'Unsupported local operation.' }
        [pscustomobject]@{ ok = $true; data = $data }
    } catch {
        $message = 'Local connector request failed. Check connector pairing, platform availability and permissions, then refresh.'
        if ($_.Exception -is [Net.WebException]) {
            if ($_.Exception.Response) {
                $message = 'Local connector rejected the request (HTTP ' + [int]$_.Exception.Response.StatusCode + '). Open the connector for details; then refresh.'
                $_.Exception.Response.Dispose()
            } elseif ($_.Exception.Status -eq [Net.WebExceptionStatus]::Timeout) {
                $message = 'The connector request timed out. A launch may already be processing; inspect the connector before retrying.'
            }
        }
        [pscustomobject]@{ ok = $false; error = $message }
    } finally { $authorization = $null }
}

$script:items = @()
$script:pending = $null
$script:catalogGeneration = 0
$script:catalogUserId = $null
$script:searchQueued = $false
$script:exitRequested = $false
$script:smokeCompleted = $false
$mutex = $null
$locked = $false
$hotkeyWindow = $null
$tray = $null
$form = $null
$pollTimer = $null
$searchTimer = $null
$smokeTimer = $null
$context = $null
try {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $mutex = New-Object Threading.Mutex($false, ('Local\InfraScope-QuickLauncher-' + $sid + '-' + ([Uri]$ConnectorOrigin).Port))
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'The quick launcher is already running for this user and connector port. Use its hotkey or tray icon.' }
    [Windows.Forms.Application]::EnableVisualStyles()
    $context = New-Object Windows.Forms.ApplicationContext
    $form = New-Object Windows.Forms.Form
    $form.Text = 'InfraScope - Quick Connect'
    $form.Size = New-Object Drawing.Size(920, 550)
    $form.MinimumSize = New-Object Drawing.Size(700, 420)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object Drawing.Font('Segoe UI', 10)
    $form.ShowInTaskbar = $false
    $form.KeyPreview = $true
    $form.BackColor = [Drawing.Color]::FromArgb(244, 247, 249)
    $form.Icon = [Drawing.SystemIcons]::Application

    $layout = New-Object Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.Padding = New-Object Windows.Forms.Padding(20)
    $layout.ColumnCount = 1; $layout.RowCount = 5
    [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute', 38)))
    [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute', 44)))
    [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent', 100)))
    [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute', 52)))
    [void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute', 40)))
    $form.Controls.Add($layout)
    $heading = New-Object Windows.Forms.Label
    $heading.Text = 'Quick Connect  /  ' + $Hotkey
    $heading.Font = New-Object Drawing.Font('Segoe UI Semibold', 16)
    $heading.AutoSize = $true
    $layout.Controls.Add($heading, 0, 0)
    $search = New-Object Windows.Forms.TextBox
    $search.Dock = 'Fill'; $search.AccessibleName = 'Search server, address, account or protocol'; $search.MaxLength = 200
    $layout.Controls.Add($search, 0, 1)
    $list = New-Object Windows.Forms.ListView
    $list.Dock = 'Fill'; $list.View = 'Details'; $list.FullRowSelect = $true; $list.MultiSelect = $false
    $list.HideSelection = $false; $list.AccessibleName = 'Authorized remote connections'
    [void]$list.Columns.Add('Server', 230)
    [void]$list.Columns.Add('Protocol', 85)
    [void]$list.Columns.Add('Address', 220)
    [void]$list.Columns.Add('Account', 260)
    $layout.Controls.Add($list, 0, 2)
    $status = New-Object Windows.Forms.Label
    $status.Dock = 'Fill'; $status.TextAlign = 'MiddleLeft'
    $status.Text = 'Use ' + $Hotkey + ' to load your authorized connections.'
    $layout.Controls.Add($status, 0, 3)
    $buttons = New-Object Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'; $buttons.FlowDirection = 'RightToLeft'
    $connectButton = New-Object Windows.Forms.Button
    $connectButton.Text = 'Connect (Enter)'; $connectButton.AutoSize = $true; $connectButton.Enabled = $false
    $refreshButton = New-Object Windows.Forms.Button
    $refreshButton.Text = 'Refresh'; $refreshButton.AutoSize = $true
    $hint = New-Object Windows.Forms.Label
    $hint.Text = 'Enter confirms this target. Esc hides. Credentials stay on the server.'
    $hint.AutoSize = $true; $hint.Padding = New-Object Windows.Forms.Padding(0, 7, 10, 0)
    $buttons.Controls.Add($connectButton); $buttons.Controls.Add($refreshButton); $buttons.Controls.Add($hint)
    $layout.Controls.Add($buttons, 0, 4)

    function Update-LauncherList {
        $list.BeginUpdate()
        try {
            $list.Items.Clear()
            foreach ($item in $script:items) {
                if (-not (Test-LauncherSearch $item $search.Text)) { continue }
                $row = New-Object Windows.Forms.ListViewItem($item.assetName)
                [void]$row.SubItems.Add($item.protocol.ToUpperInvariant())
                $address = $item.host
                if ($address.Contains(':')) { $address = '[' + $address + ']' }
                [void]$row.SubItems.Add($address + ':' + $item.port)
                [void]$row.SubItems.Add($item.username + ' / ' + $item.accountName)
                $row.Tag = $item
                [void]$list.Items.Add($row)
            }
            if ($list.Items.Count -gt 0) { $list.Items[0].Selected = $true }
            $connectButton.Enabled = -not $script:pending -and $list.SelectedItems.Count -eq 1
        } finally { $list.EndUpdate() }
    }

    function Start-LauncherRequest([string]$Operation, $Selection) {
        if ($script:pending -or $SmokeTest) { return }
        $payload = ''
        $query = ''
        if ($Operation -eq 'open') {
            if (-not $script:catalogUserId -or $Selection.userId -cne $script:catalogUserId) {
                $status.Text = 'The catalog identity changed. Refresh before connecting.'
                return
            }
            $payload = @{ assetId = $Selection.assetId; accountId = $Selection.accountId; protocol = $Selection.protocol; userId = $Selection.userId;
                confirmed = $true; idempotencyKey = [Guid]::NewGuid().ToString() } | ConvertTo-Json -Compress
            $status.Text = 'Starting ' + $Selection.protocol.ToUpperInvariant() + ' for ' + $Selection.assetName + '...'
            $search.Enabled = $false
        } else {
            try { $query = Get-LauncherQuery $search.Text } catch {
                $status.Text = $_.Exception.Message; $script:searchQueued = $false; return
            }
            $script:searchQueued = $false
            $script:catalogUserId = $null
            $script:items = @(); Update-LauncherList
            $status.Text = 'Loading authorized connections from the paired platform...'
        }
        $connectButton.Enabled = $false; $refreshButton.Enabled = $false; $list.Enabled = $false
        $worker = [PowerShell]::Create()
        try {
            [void]$worker.AddScript($requestWorker.ToString()).AddArgument($ConnectorOrigin).AddArgument($Operation).AddArgument($payload).AddArgument($query)
            $handle = $worker.BeginInvoke()
            $script:pending = @{ Worker = $worker; Handle = $handle; Operation = $Operation; Selection = $Selection;
                Query = $query; Generation = $script:catalogGeneration }
        } catch {
            $worker.Dispose()
            $list.Enabled = $true; $refreshButton.Enabled = $true; $search.Enabled = $true
            $status.Text = 'The connector request could not be started. Refresh to retry.'
        }
    }

    function Show-Launcher {
        $form.Show(); $form.WindowState = 'Normal'; $form.Activate()
        [void][InfraScope.QuickLauncher.HotkeyWindow]::SetForegroundWindow($form.Handle)
        [void]$search.Focus(); $search.SelectAll()
        if ($script:pending -and $script:pending.Operation -eq 'open') { return }
        $search.Text = ''
        $searchTimer.Stop()
        $script:catalogGeneration++
        $script:catalogUserId = $null
        $script:items = @(); Update-LauncherList
        $script:searchQueued = $true
        Start-LauncherRequest 'catalog' $null
    }

    function Open-LauncherSelection {
        if (-not $script:pending -and $list.SelectedItems.Count -eq 1) {
            Start-LauncherRequest 'open' $list.SelectedItems[0].Tag
        }
    }

    $searchTimer = New-Object Windows.Forms.Timer
    $searchTimer.Interval = 250
    $searchTimer.Add_Tick({
        $searchTimer.Stop()
        Start-LauncherRequest 'catalog' $null
    })
    $search.Add_TextChanged({
        $script:catalogGeneration++
        $script:catalogUserId = $null
        $script:items = @(); Update-LauncherList
        $script:searchQueued = $true
        $searchTimer.Stop(); $searchTimer.Start()
        $status.Text = 'Searching authorized connections on the platform...'
    })
    $search.Add_KeyDown({
        param($sender, $event)
        if ($event.KeyCode -eq [Windows.Forms.Keys]::Down -and $list.Items.Count -gt 0) {
            [void]$list.Focus(); $list.Items[0].Focused = $true; $event.SuppressKeyPress = $true
        }
    })
    $list.Add_SelectedIndexChanged({ $connectButton.Enabled = -not $script:pending -and $list.SelectedItems.Count -eq 1 })
    $list.Add_DoubleClick({ Open-LauncherSelection })
    $connectButton.Add_Click({ Open-LauncherSelection })
    $refreshButton.Add_Click({
        $searchTimer.Stop(); $script:catalogGeneration++
        Start-LauncherRequest 'catalog' $null
    })
    $form.Add_KeyDown({
        param($sender, $event)
        if ($event.KeyCode -eq [Windows.Forms.Keys]::Escape) { $form.Hide(); $event.SuppressKeyPress = $true }
        elseif ($event.KeyCode -eq [Windows.Forms.Keys]::Enter) { Open-LauncherSelection; $event.SuppressKeyPress = $true }
    })
    $form.Add_FormClosing({
        param($sender, $event)
        if (-not $script:exitRequested -and $event.CloseReason -eq [Windows.Forms.CloseReason]::UserClosing) {
            $event.Cancel = $true; $form.Hide()
        } else { $context.ExitThread() }
    })

    $tray = New-Object Windows.Forms.NotifyIcon
    $tray.Icon = $form.Icon; $tray.Text = 'InfraScope Quick Connect'
    $menu = New-Object Windows.Forms.ContextMenuStrip
    $showMenu = $menu.Items.Add('Show (' + $Hotkey + ')')
    $refreshMenu = $menu.Items.Add('Refresh connections')
    [void]$menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
    $exitMenu = $menu.Items.Add('Exit')
    $showMenu.Add_Click({ Show-Launcher })
    $refreshMenu.Add_Click({ Show-Launcher })
    $exitMenu.Add_Click({ $script:exitRequested = $true; $context.ExitThread() })
    $tray.ContextMenuStrip = $menu
    $tray.Add_DoubleClick({ Show-Launcher })
    $tray.Visible = $true
    $hotkeyWindow = New-Object InfraScope.QuickLauncher.HotkeyWindow([uint32]$hotkeyConfig.Modifiers, [uint32]$hotkeyConfig.VirtualKey)
    $hotkeyWindow.Add_Pressed({ Show-Launcher })

    $pollTimer = New-Object Windows.Forms.Timer
    $pollTimer.Interval = 100
    $pollTimer.Add_Tick({
        if (-not $script:pending -or -not $script:pending.Handle.IsCompleted) { return }
        $completed = $script:pending
        $script:pending = $null
        try {
            $results = @($completed.Worker.EndInvoke($completed.Handle))
            # Ignore late catalog responses after the query changed; they must not replace current identity or results.
            if ($completed.Operation -eq 'catalog' -and $completed.Generation -ne $script:catalogGeneration) { return }
            if ($completed.Worker.HadErrors -or $results.Count -ne 1) { throw 'The connector worker did not return a valid result.' }
            $result = $results[0]
            if (-not $result.ok) { throw ([string]$result.error) }
            if ($completed.Operation -eq 'catalog') {
                $script:items = @(Get-LauncherCatalog $result.data $PlatformOrigin)
                $script:catalogUserId = $result.data.userId
                Update-LauncherList
                $status.Text = [string]$script:items.Count + ' authorized connections. Search by server, address, account or protocol.'
                if ($script:items.Count -eq 0) { $status.Text = 'No authorized connections. Add a server and grant yourself access in the platform, then refresh.' }
                if ($result.data.truncated) { $status.Text = 'Showing at most 200 authorized matches. Keep typing to search beyond these results.' }
            } else {
                $data = $result.data
                if ($data.ok -ne $true) { throw 'The connector did not accept this connection.' }
                if ($completed.Selection.protocol -eq 'rdp') {
                    if ($data.state -cne 'started' -or ($data.pid -isnot [int] -and $data.pid -isnot [long]) -or $data.pid -le 0) {
                        throw 'The connector has not confirmed that mstsc started. Check its local task status.'
                    }
                    $status.Text = 'mstsc started. This does NOT prove authentication or a usable remote desktop; verify the mstsc window.'
                } else {
                    if ($data.state -cne 'open_browser') { throw 'The connector did not return a browser workspace.' }
                    $url = Get-LauncherBrowserUrl ([string]$data.url) $PlatformOrigin $completed.Selection
                    Start-Process -FilePath $url
                    $status.Text = 'Workspace opened in the browser. Verify the host fingerprint and session there; no connection is marked complete.'
                }
            }
        } catch {
            if ($completed.Operation -eq 'catalog') { $script:items = @(); $script:catalogUserId = $null; Update-LauncherList }
            $status.Text = 'Failed: ' + $_.Exception.Message
        } finally {
            $completed.Worker.Dispose()
            $list.Enabled = $true; $refreshButton.Enabled = $true; $search.Enabled = $true
            $connectButton.Enabled = $list.SelectedItems.Count -eq 1
            if ($script:searchQueued -and -not $searchTimer.Enabled) { Start-LauncherRequest 'catalog' $null }
        }
    })
    $pollTimer.Start()
    if ($SmokeTest) {
        # Exercise creation and registration only: no network, key injection or remote launch.
        [void]$form.Handle
        $smokeTimer = New-Object Windows.Forms.Timer
        $smokeTimer.Interval = 250
        $smokeTimer.Add_Tick({
            $smokeTimer.Stop(); $script:smokeCompleted = $true; $script:exitRequested = $true; $context.ExitThread()
        })
        $smokeTimer.Start()
    }
    [Windows.Forms.Application]::Run($context)
} catch {
    if (-not $SmokeTest) {
        [void][Windows.Forms.MessageBox]::Show($_.Exception.Message, 'InfraScope Quick Connect', 'OK', 'Error')
    }
    throw
} finally {
    if ($pollTimer) { $pollTimer.Stop(); $pollTimer.Dispose() }
    if ($searchTimer) { $searchTimer.Stop(); $searchTimer.Dispose() }
    if ($smokeTimer) { $smokeTimer.Stop(); $smokeTimer.Dispose() }
    if ($hotkeyWindow) { $hotkeyWindow.Dispose() }
    if ($tray) { $tray.Visible = $false; $tray.Dispose() }
    if ($script:pending) { $script:pending.Worker.Stop(); $script:pending.Worker.Dispose(); $script:pending = $null }
    if ($form) { $form.Dispose() }
    if ($context) { $context.Dispose() }
    if ($locked -and $mutex) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
}
if ($SmokeTest) {
    [pscustomobject]@{ ok = $script:smokeCompleted; formCreated = $true; hotkeyRegistered = $true;
        trayCreated = $true; resourcesReleased = $true; networkCalls = 0; remoteLaunches = 0;
        hotkeyPhysicallyPressed = $false; hotkey = $Hotkey } | ConvertTo-Json -Compress
}
