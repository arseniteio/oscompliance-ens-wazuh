$dc = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if ($dc) {
  Import-Module ActiveDirectory
  # Ask this domain controller by name: the DC locator needs the domain SRV records, and a DC with broken DNS has none.
  $groups = @(Get-ADGroup -Server $env:COMPUTERNAME -Filter * -ResultSetSize 5000 -Properties member | ForEach-Object {
    [ordered]@{ name = $_.SamAccountName; sid = $_.SID.Value; members = @($_.member | ForEach-Object { ($_ -split '(?<!\\),')[0] -replace '^CN=' }) } })
} else {
  $computer = $env:COMPUTERNAME
  $groups = @(Get-LocalGroup | ForEach-Object {
    $adsi = [ADSI]"WinNT://$computer/$($_.Name),group"
    $members = @($adsi.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null) })
    [ordered]@{ name = $_.Name; sid = $_.SID.Value; members = $members } })
}
ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ source = $(if ($dc) { 'active_directory' } else { 'sam' }); computer = $env:COMPUTERNAME; groups = $groups })
