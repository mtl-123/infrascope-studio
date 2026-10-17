[CmdletBinding()]
param([ValidateSet('Status','Install','InstallPolicy')][string]$Mode='Status',[string]$PolicyEntry,[string]$ResultPath)
$ErrorActionPreference='Stop'
[Console]::InputEncoding=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$subject='CN=Pulse RDP Launcher'
$policyPaths=@('HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services')
function Read-Policy {
 $values=@()
 foreach($p in $policyPaths){try{$v=(Get-ItemProperty -LiteralPath $p -Name TrustedCertThumbprints -ErrorAction Stop).TrustedCertThumbprints;$values+=($v -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})}catch{}}
 return @($values | Select-Object -Unique)
}
function Find-Certificate([int]$Days=30){
 $s=New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
 try{$s.Open('ReadOnly');return @($s.Certificates | Where-Object {$_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays($Days) -and $_.NotBefore -le (Get-Date)} | Sort-Object NotAfter -Descending | Select-Object -First 1)}finally{$s.Close()}
}
function Hash-Policy($cert){
 $admx=Join-Path $env:SystemRoot 'PolicyDefinitions\TerminalServer.admx';$sha256=$false
 if(Test-Path -LiteralPath $admx){$sha256=(Get-Content -LiteralPath $admx -Raw).Contains('DisableSHA1CertThumbprints')}
 if($sha256){$h=[System.Security.Cryptography.SHA256]::Create();try{$value=([BitConverter]::ToString($h.ComputeHash($cert.RawData))).Replace('-','')}finally{$h.Dispose()};return @{Entry=('sha256:'+$value);Hash='sha256'}}
 return @{Entry=$cert.Thumbprint;Hash='sha1'}
}
function Has-PublicTrust([string]$Name,$cert){$s=New-Object System.Security.Cryptography.X509Certificates.X509Store($Name,'CurrentUser');try{$s.Open('ReadOnly');return @($s.Certificates | Where-Object {$_.Thumbprint -eq $cert.Thumbprint}).Count -gt 0}finally{$s.Close()}}
function Signing-Status {
 $certs=@(Find-Certificate 30)
 if($certs.Count -eq 0){return @{ok=$true;configured=$false;reason='signing certificate is not installed'}}
 $cert=$certs[0];$p=Hash-Policy $cert;$root=Has-PublicTrust 'Root' $cert;$publisher=Has-PublicTrust 'TrustedPublisher' $cert;$policy=(Read-Policy) -contains $p.Entry
 return @{ok=$true;configured=($root -and $publisher -and $policy);publisher='Pulse RDP Launcher';certificateThumbprint=$cert.Thumbprint;policyThumbprint=$p.Entry;signingHash=$p.Hash;rootTrusted=$root;publisherTrusted=$publisher;policyConfigured=$policy;expires=$cert.NotAfter.ToUniversalTime().ToString('o')}
}
function Emit($value){$j=$value|ConvertTo-Json -Compress -Depth 6;if($ResultPath){[IO.File]::WriteAllText($ResultPath,$j,(New-Object Text.UTF8Encoding($false)))};[Console]::Out.WriteLine($j);[Console]::Out.Flush()}
if($MyInvocation.InvocationName -eq '.') { return }
try {
 if($Mode -eq 'InstallPolicy'){
  if($PolicyEntry -notmatch '^(sha256:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40})$'){throw 'Invalid policy fingerprint'}
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
  if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator approval is required'}
  $p=$policyPaths[1];$existing=@();try{$v=(Get-ItemProperty -LiteralPath $p -Name TrustedCertThumbprints -ErrorAction Stop).TrustedCertThumbprints;$existing=@($v -split ','|ForEach-Object {$_.Trim()}|Where-Object {$_})}catch{}
  $merged=@($existing+$PolicyEntry|Select-Object -Unique);if(-not(Test-Path -LiteralPath $p)){New-Item -Path $p -Force|Out-Null};New-ItemProperty -LiteralPath $p -Name TrustedCertThumbprints -Value ($merged -join ',') -PropertyType String -Force|Out-Null
  Emit @{ok=$true;policyConfigured=$true};exit 0
 }
 if($Mode -eq 'Status'){Emit (Signing-Status);exit 0}
 Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
 Import-Module PKI -ErrorAction Stop
 if(-not(Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)){New-PSDrive -Name Cert -PSProvider Certificate -Root '\'|Out-Null}
 $certs=@(Find-Certificate 30)
 if($certs.Count -gt 0){$cert=$certs[0]}else{$cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -FriendlyName 'Pulse trusted RDP file publisher' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(3) -CertStoreLocation 'Cert:\CurrentUser\My'}
 foreach($name in @('Root','TrustedPublisher')){
  if(-not(Has-PublicTrust $name $cert)){$s=New-Object Security.Cryptography.X509Certificates.X509Store($name,'CurrentUser');$public=New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert));try{$s.Open('ReadWrite');$s.Add($public)}finally{$s.Close();$public.Reset()}}
 }
 $p=Hash-Policy $cert
 if(-not((Read-Policy) -contains $p.Entry)){
  $result=Join-Path ([IO.Path]::GetTempPath()) ('pulse-rdp-policy-'+[Guid]::NewGuid().ToString('N')+'.json')
  try{
   $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
   $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Mode InstallPolicy -PolicyEntry "'+$p.Entry+'" -ResultPath "'+$result+'"'
   $proc=Start-Process -FilePath $ps -ArgumentList $args -Verb RunAs -WindowStyle Hidden -Wait -PassThru
   if($proc.ExitCode -ne 0 -or -not(Test-Path -LiteralPath $result)){throw 'Approve the Windows administrator prompt, then retry; user certificate trust may already be installed'}
   $r=Get-Content -LiteralPath $result -Raw|ConvertFrom-Json
   if(-not $r.ok){throw 'Machine policy installation failed; user certificate trust may already be installed'}
  }finally{if(Test-Path -LiteralPath $result){Remove-Item -LiteralPath $result -Force -ErrorAction SilentlyContinue}}
 }
 Emit (Signing-Status)
}catch{Emit @{ok=$false;configured=$false;policyConfigured=$false;error=$_.Exception.Message};[Console]::Error.WriteLine($_.Exception.Message);exit 1}
