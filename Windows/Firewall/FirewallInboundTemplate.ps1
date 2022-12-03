$PortToApp = Get-NetTCPConnection | Select-Object -Property LocalPort,@{name='ProcessName';expression={(Get-Process -Id $_.OwningProcess). Path}},CreationTime

$PortTable = @{}

$PortToApp | ForEach-Object {$PortTable.Add($_.LocalPort, $_.ProcessName)}

Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName "RDP" -Name "RDP" -Direction Inbound -Action Allow -LocalPort 3389 -Protocol TCP -Enabled True -Profile Any
New-NetFirewallRule -DisplayName "SSH" -Name "SSH" -Direction Inbound -Action Allow -LocalPort 22 -Protocol TCP -Enabled True -Profile Any
New-NetFirewallRule -DisplayName "WinRM" -Name "WinRM" -Direction Inbound -Action Allow -LocalPort 5985 -Protocol TCP -Enabled True -Profile Any -RemoteAddress LocalSubnet



Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 -LogAllowed False -LogFileName "%systemroot%\System32\LogFiles\Firewall\pfirewall.log"

Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow  -Enabled True

netsh a s a state off

netsh a s a state on

Start-Sleep -Seconds 45

$LogIn = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "RECEIVE"

for ($i = 0; $i -lt $LogIn.Length; $i++) {$LogIn[$i] = $LogIn[$i].ToString().Split(" ")[5] + ":" + $LogIn[$i].ToString().Split(" ")[7]}

$SocketsIn = $LogIn | Select-Object -Unique

$SocketsIn | ForEach-Object {
    if($PortTable.Values -eq $NULL) {
        New-NetFirewallRule -DisplayName "$_" -Name "$_" -Direction Inbound -Action Allow -LocalPort $_.split(":")[1] -Protocol TCP -Enabled True -Profile Any
    } else {
        $Program = $_.split(":")[1];
        New-NetFirewallRule -DisplayName "$_" -Name "$_" -Program ($PortTable.GetEnumerator() | Where-Object key -eq $Program | Select-Object -expand Value) -Direction Inbound -Action Allow -LocalPort $_.split(":")[1] -Protocol TCP -Enabled True -Profile Any}
}

