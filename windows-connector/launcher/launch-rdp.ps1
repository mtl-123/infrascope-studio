[CmdletBinding()]
param([switch]$SelfTest,[switch]$Recover)
$ErrorActionPreference='Stop'
[Console]::InputEncoding=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class InfraCredential {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
 public struct CREDENTIAL {public uint Flags; public uint Type; public string TargetName; public string Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist; public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;}
 [DllImport("advapi32.dll",EntryPoint="CredWriteW",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool Write(ref CREDENTIAL c,uint flags);
 [DllImport("advapi32.dll",EntryPoint="CredReadW",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool Read(string name,uint type,uint flags,out IntPtr ptr);
 [DllImport("advapi32.dll",EntryPoint="CredDeleteW",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool Delete(string name,uint type,uint flags);
 [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr p);
}
'@
$mstsc=Join-Path $env:SystemRoot 'System32\mstsc.exe';$rdpsign=Join-Path $env:SystemRoot 'System32\rdpsign.exe'
function Emit($v){[Console]::Out.WriteLine(($v|ConvertTo-Json -Compress -Depth 6));[Console]::Out.Flush()}
if($SelfTest){Emit @{ok=$true;credentialApi=$true;mstsc=(Test-Path -LiteralPath $mstsc);rdpsign=(Test-Path -LiteralPath $rdpsign)};exit 0}
function Read-Cred([string]$target){$ptr=[IntPtr]::Zero;if([InfraCredential]::Read($target,1,0,[ref]$ptr)){try{$c=[Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[type][InfraCredential+CREDENTIAL]);return @{exists=$true;comment=$c.Comment;username=$c.UserName;lastWritten=($c.LastWritten.dwHighDateTime.ToString('X8')+$c.LastWritten.dwLowDateTime.ToString('X8'))}}finally{[InfraCredential]::CredFree($ptr)}};$err=[Runtime.InteropServices.Marshal]::GetLastWin32Error();if($err -eq 1168){return @{exists=$false}};throw 'Cannot safely read Credential Manager'}
function Private-Directory([string]$p){if(-not(Test-Path -LiteralPath $p)){New-Item -ItemType Directory -Path $p -Force|Out-Null};$acl=Get-Acl -LiteralPath $p;$acl.SetAccessRuleProtection($true,$false);$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.SetAccessRule($rule);Set-Acl -LiteralPath $p -AclObject $acl}
$leaseDir=Join-Path $env:LOCALAPPDATA 'InfraScope\leases';Private-Directory $leaseDir
function Cleanup-Lease($lease){
 $ok=$true
 if($lease.credentialWritten){try{$c=Read-Cred $lease.target;if($c.exists){if($c.comment -ceq $lease.marker -and $c.username -ceq $lease.username -and $lease.lastWritten -and $c.lastWritten -ceq $lease.lastWritten){if(-not[InfraCredential]::Delete($lease.target,1,0)){$ok=$false}}else{$ok=$false}}}catch{$ok=$false}}
 try{if($lease.file -and (Split-Path -Leaf $lease.file) -eq ('pulse-rdp-'+$lease.id+'.rdp') -and [IO.Path]::GetDirectoryName($lease.file) -eq [IO.Path]::GetTempPath().TrimEnd('\')){Remove-Item -LiteralPath $lease.file -Force -ErrorAction SilentlyContinue;if(Test-Path -LiteralPath $lease.file){$ok=$false}}}catch{$ok=$false}
 return $ok
}
function Target-Mutex([string]$target){
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $hash=[Security.Cryptography.SHA256]::Create()
 try{$key=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid+'|'+$target)))).Replace('-','')}finally{$hash.Dispose()}
 return (New-Object Threading.Mutex($false,('Local\InfraScope-RDP-'+$key)))
}
if($Recover){
 $recovered=0;$failed=0;$busy=0
 foreach($f in Get-ChildItem -LiteralPath $leaseDir -Filter '*.json' -File){
  $recoverMutex=$null;$recoverLocked=$false
  try{
   $l=Get-Content -LiteralPath $f.FullName -Raw|ConvertFrom-Json
   if([DateTime]::Parse($l.expires).ToUniversalTime() -lt [DateTime]::UtcNow){
    $recoverMutex=Target-Mutex $l.target
    try{$recoverLocked=$recoverMutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$recoverLocked=$true}
    if(-not $recoverLocked){$busy++;continue}
    if(Cleanup-Lease $l){Remove-Item -LiteralPath $f.FullName -Force;$recovered++}else{$failed++}
   }
  }catch{$failed++}finally{if($recoverLocked -and $recoverMutex){$recoverMutex.ReleaseMutex()};if($recoverMutex){$recoverMutex.Dispose()}}
 }
 Emit @{ok=($failed -eq 0);recovered=$recovered;cleanupFailed=$failed;busy=$busy};exit 0
}
$mutex=$null;$locked=$false;$lease=$null;$leasePath=$null;$wrote=$false
try {
 if(-not[Environment]::UserInteractive){throw 'An interactive Windows user session is required'}
 $c=[Console]::In.ReadToEnd()|ConvertFrom-Json
 $address=([string]$c.address).Trim();$username=([string]$c.username).Trim();$password=[string]$c.password
 if(-not $address -or $address.Length -gt 255 -or $address -match '[\s\x00]' -or $address -match '[/\\@?#]'){throw 'Invalid target address'}
 if($c.port -isnot [int] -and $c.port -isnot [long]){throw 'Invalid RDP port'};$port=[int]$c.port;if($port -lt 1 -or $port -gt 65535){throw 'Invalid RDP port'}
 if($username.Length -gt 512 -or $username -match '[\r\n\x00]'){throw 'Invalid username'};if($password.Length -gt 2048 -or [Text.Encoding]::Unicode.GetByteCount($password) -gt 2560){throw 'Password is too long'};if($password -and -not $username){throw 'Username is required when a password is provided'}
 foreach($flag in @('redirectClipboard','redirectDrives','fullscreen','multiMonitor')){if($c.$flag -isnot [bool]){throw 'Invalid boolean option'}}
 $drive='';if($c.redirectDrives){if($c.driveMode -eq 'custom'){$parts=@();foreach($part in ([string]$c.driveList -split '[,;]')){$v=$part.Trim();if(-not $v){continue};if($v -notmatch '^[A-Za-z]:\\?$'){throw 'Invalid drive list'};$parts+=($v.Substring(0,1).ToUpperInvariant()+':\')};if($parts.Count -eq 0){throw 'Invalid drive list'};$drive=(@($parts|Select-Object -Unique)-join ';')}elseif($c.driveMode -eq 'all'){$drive='*'}else{throw 'Invalid drive mode'}}
 . (Join-Path $PSScriptRoot 'setup-rdp-signing.ps1')
 $status=Signing-Status
 if(-not $status.configured){Emit @{ok=$false;code='signing_setup_required';error='One-click RDP signing setup is required'};exit 2}
 if(-not(Test-Path -LiteralPath $mstsc) -or -not(Test-Path -LiteralPath $rdpsign)){throw 'mstsc or rdpsign is not installed'}
 $target='TERMSRV/'+$address.ToLowerInvariant();$mutex=Target-Mutex $target;try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true};if(-not $locked){Emit @{ok=$false;code='credential_target_busy';error='Another launch currently holds this credential target'};exit 2}
 if($password -and (Read-Cred $target).exists){Emit @{ok=$false;code='existing_credential';error='Existing TERMSRV credential detected; it will not be overwritten. Use an explicitly authorized interactive account or manage it yourself.'};exit 2}
 $id=[Guid]::NewGuid().ToString('N');$file=Join-Path ([IO.Path]::GetTempPath()) ('pulse-rdp-'+$id+'.rdp');$leasePath=Join-Path $leaseDir ($id+'.json');$marker='InfraScope:'+ $id
 $lease=@{id=$id;target=$target;username=$username;marker=$marker;file=$file;expires=[DateTime]::UtcNow.AddSeconds(60).ToString('o');credentialWritten=([bool]($username -and $password));lastWritten=''}
 [IO.File]::WriteAllText($leasePath,($lease|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
 if($username -and $password){
  $native=New-Object InfraCredential+CREDENTIAL;$native.Flags=0;$native.Type=1;$native.TargetName=$target;$native.Comment=$marker;$native.Persist=1;$native.UserName=$username;$ptr=[Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($password)
  try{$native.CredentialBlob=$ptr;$native.CredentialBlobSize=[Text.Encoding]::Unicode.GetByteCount($password);if(-not[InfraCredential]::Write([ref]$native,0)){throw 'Credential Manager write failed'}}finally{[Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($ptr)}
  $wrote=$true;$lease.credentialWritten=$true;$lease.lastWritten=(Read-Cred $target).lastWritten;[IO.File]::WriteAllText($leasePath,($lease|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
 }
 $formatted=$address+':'+$port;if($address.Contains(':')){$formatted='['+$address.Trim([char[]]'[]')+']:'+$port}
 $prompt=1;if($username -and $password){$prompt=0};$screen=1;if($c.fullscreen){$screen=2}
 $lines=@(
 "full address:s:$formatted"
 "username:s:$username"
 "prompt for credentials:i:$prompt"
 'authentication level:i:2'
 'enablecredsspsupport:i:1'
 'negotiate security layer:i:1'
 ("redirectclipboard:i:"+([int]$c.redirectClipboard))
 ("redirectdrives:i:"+([int]$c.redirectDrives))
 "drivestoredirect:s:$drive"
 "screen mode id:i:$screen"
 ("use multimon:i:"+([int]$c.multiMonitor))
 'smart sizing:i:1'
 'dynamic resolution:i:1'
 'networkautodetect:i:1'
 'bandwidthautodetect:i:1'
 'connection type:i:7'
 'compression:i:1'
 'bitmapcachepersistenable:i:1'
 )
 [IO.File]::WriteAllLines($file,$lines,[Text.Encoding]::Unicode)
 $fileAcl=Get-Acl -LiteralPath $file;$fileAcl.SetAccessRuleProtection($true,$false);$fileSid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$fileAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($fileSid,'FullControl','Allow')));Set-Acl -LiteralPath $file -AclObject $fileAcl
 $result=& $rdpsign ('/'+$status.signingHash) $status.certificateThumbprint /q $file 2>&1
 if($LASTEXITCODE -ne 0){throw 'rdpsign failed; unsigned RDP file was not launched'}
 $p=Start-Process -FilePath $mstsc -ArgumentList ('"'+$file+'"') -PassThru
 Emit @{ok=$true;pid=$p.Id;target=$formatted;state='started'}
 $password=$null;$c.password=$null
 Start-Sleep -Seconds 30
}catch{Emit @{ok=$false;code='launch_failed';error=$_.Exception.Message}}
finally{
 if($lease){$clean=Cleanup-Lease $lease;if($clean){Remove-Item -LiteralPath $leasePath -Force -ErrorAction SilentlyContinue};Emit @{type='cleanup';ok=$clean;state=$(if($clean){'cleanup_completed'}else{'cleanup_failed'})}}
 if($locked -and $mutex){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}
}
