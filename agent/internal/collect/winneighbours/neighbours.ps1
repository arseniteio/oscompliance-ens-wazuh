$rows = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object {
  [ordered]@{ ip = [string]$_.IPAddress; mac = [string]$_.LinkLayerAddress; interface = [string]$_.InterfaceAlias; state = [string]$_.State } })
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{ neighbours = $rows })
