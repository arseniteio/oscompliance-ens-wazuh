$keys = @(
  @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; names = 'InactivityTimeoutSecs','LegalNoticeCaption','LegalNoticeText','EnableLUA','ConsentPromptBehaviorAdmin','FilterAdministratorToken','LocalAccountTokenFilterPolicy','DontDisplayLastUserName' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; names = 'fDenyTSConnections' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; names = 'UserAuthentication','SecurityLayer','MinEncryptionLevel','PortNumber' },
  @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; names = 'UserAuthentication','SecurityLayer','MinEncryptionLevel','MaxIdleTime','MaxDisconnectionTime','fPromptForPassword','fDisableCdm' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; names = 'LmCompatibilityLevel','NoLMHash','RestrictAnonymous','RestrictAnonymousSAM','EveryoneIncludesAnonymous','LimitBlankPasswordUse','RunAsPPL' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; names = 'NTLMMinServerSec','NTLMMinClientSec' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; names = 'SMB1','RequireSecuritySignature','EnableSecuritySignature','RestrictNullSessAccess' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; names = 'RequireSecuritySignature','EnableSecuritySignature' },
  @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; names = 'AllowBasic','AllowUnencryptedTraffic' },
  @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; names = 'AllowBasic','AllowUnencryptedTraffic' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'; names = 'MaxSize','Retention' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'; names = 'MaxSize','Retention' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'; names = 'MaxSize','Retention' },
  @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; names = 'MaxSize','Retention' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; names = 'Enabled' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; names = 'Enabled' },
  @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; names = 'Enabled' },
  @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; names = 'EnableMulticast' },
  @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; names = 'NoDriveTypeAutoRun','NoAutorun' }
)
$registry = @(foreach ($k in $keys) {
  $item = Get-ItemProperty -LiteralPath $k.path -ErrorAction SilentlyContinue
  $values = [ordered]@{}
  if ($item) { foreach ($n in $k.names) { $v = $item.$n; if ($null -ne $v) { $values[$n] = (@($v) -join "`n") } } }
  [ordered]@{ path = ($k.path -replace '^HKLM:\\', 'HKLM\'); exists = [bool]$item; values = $values }
})

$dir = Join-Path ([IO.Path]::GetTempPath()) ('oscompliance-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  $inf = Join-Path $dir 'secpol.inf'
  $secedit = @()
  $seceditError = ''
  & "$env:SystemRoot\System32\secedit.exe" /export /cfg $inf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
  # Get-Content tags each line with PSPath and friends, and Windows PowerShell's ConvertTo-Json writes such a line as an object.
  if ($LASTEXITCODE -eq 0) { $secedit = @([IO.File]::ReadAllLines($inf, [Text.Encoding]::Unicode)) } else { $seceditError = "secedit exit $LASTEXITCODE" }

  $csv = Join-Path $dir 'audit.csv'
  $auditpol = @()
  $auditpolError = ''
  & "$env:SystemRoot\System32\auditpol.exe" /backup /file:$csv | Out-Null
  if ($LASTEXITCODE -eq 0) {
    $auditpol = @(Import-Csv -LiteralPath $csv | Where-Object { $_.'Subcategory GUID' } | ForEach-Object {
      [ordered]@{ subcategory = $_.Subcategory; guid = $_.'Subcategory GUID'; value = $_.'Setting Value' } })
  } else { $auditpolError = "auditpol exit $LASTEXITCODE" }
} finally {
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}

ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ secedit = $secedit; secedit_error = $seceditError; auditpol = $auditpol; auditpol_error = $auditpolError; registry = $registry })
