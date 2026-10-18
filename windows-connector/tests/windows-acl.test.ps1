[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this test with Windows PowerShell 5.1; it must not be counted as a skipped pass.'
}
$launcher = Join-Path (Split-Path -Parent $PSScriptRoot) 'launcher\launch-rdp.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Launcher parse failed.' }
# Load only the ACL helpers: never execute the launcher, credential APIs, signing or recovery.
foreach ($name in @('Private-Directory', 'Private-File')) {
    $definitions = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
    if ($definitions.Count -ne 1) { throw "Missing or duplicate helper: $name" }
    . ([ScriptBlock]::Create($definitions[0].Extent.Text))
}

$temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$owned = [IO.Path]::GetFullPath((Join-Path $temp ('infrascope-acl-test-' + [Guid]::NewGuid().ToString('N'))))
if (-not $owned.StartsWith($temp + '\', [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $owned)) {
    throw 'Temporary test directory is not a new child of TEMP.'
}
$file = Join-Path $owned 'owned-file.txt'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$created = $false
function Assert-PrivateACL([string]$Path, [string]$OriginalOwner, [string]$OriginalGroup) {
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw "DACL inheritance remains enabled: $Path" }
    if ($acl.Owner -ne $OriginalOwner -or $acl.Group -ne $OriginalGroup) { throw 'ACL helper changed owner or group.' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference -ne $sid -or $rules[0].IsInherited -or
        $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') {
        throw "DACL is not restricted to the current user: $Path"
    }
}
try {
    New-Item -ItemType Directory -Path $owned | Out-Null
    $created = $true
    $originalDirectory = Get-Acl -LiteralPath $owned
    Private-Directory $owned
    Assert-PrivateACL $owned $originalDirectory.Owner $originalDirectory.Group
    [IO.File]::WriteAllText($file, 'Isolated ACL test; no remote credential or RDP launch.')
    $originalFile = Get-Acl -LiteralPath $file
    Private-File $file
    Assert-PrivateACL $file $originalFile.Owner $originalFile.Group
    Private-Directory $owned
    Private-File $file
    Assert-PrivateACL $owned $originalDirectory.Owner $originalDirectory.Group
    Assert-PrivateACL $file $originalFile.Owner $originalFile.Group
    if ([IO.File]::ReadAllText($file) -notmatch '^Isolated ACL test') { throw 'ACL operation changed file contents.' }
    [pscustomobject]@{ ok = $true; directoryCurrentUserOnly = $true; fileCurrentUserOnly = $true;
        ownerAndGroupPreserved = $true; repeatApply = $true; windowsPowerShell = $PSVersionTable.PSVersion.ToString() } | ConvertTo-Json -Compress
} finally {
    if ($created) {
        $resolved = (Get-Item -LiteralPath $owned -Force).FullName
        if ($resolved -ne $owned -or -not $resolved.StartsWith($temp + '\', [StringComparison]::OrdinalIgnoreCase) -or
            ((Get-Item -LiteralPath $resolved -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Cleanup refused: temporary test directory changed identity.'
        }
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force }
        # Nonrecursive removal refuses any unexpected additional content.
        [IO.Directory]::Delete($owned, $false)
    }
}
