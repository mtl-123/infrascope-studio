[CmdletBinding()]
param([ValidateSet('Identity','Protect','Unprotect')][string]$Mode='Identity')
$ErrorActionPreference='Stop'
[Console]::InputEncoding=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
Add-Type -AssemblyName System.Security
try{
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $h=[Security.Cryptography.SHA256]::Create();try{$sidHash=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
 if($Mode -eq 'Identity'){$value=@{windowsUserHash=$sidHash;interactive=[Environment]::UserInteractive;computer=$env:COMPUTERNAME}}
 else{
  $inputData=[Console]::In.ReadToEnd()|ConvertFrom-Json
  if($Mode -eq 'Protect'){$bytes=[Text.Encoding]::UTF8.GetBytes([string]$inputData.value);try{$protected=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);$value=@{protected=[Convert]::ToBase64String($protected)}}finally{[Array]::Clear($bytes,0,$bytes.Length)}}
  else{$bytes=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([string]$inputData.protected),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);try{$value=@{value=[Text.Encoding]::UTF8.GetString($bytes)}}finally{[Array]::Clear($bytes,0,$bytes.Length)}}
 }
 [Console]::Out.WriteLine(($value|ConvertTo-Json -Compress -Depth 5))
}catch{[Console]::Error.WriteLine('Windows user secret protection failed');exit 1}
