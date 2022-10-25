Get-NetFirewallRule | Remove-NetFirewallRule

Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 -LogAllowed False -LogFileName "%systemroot%\System32\LogFiles\Firewall\pfirewall.log"

Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block -Enabled True

netsh a s a state off

netsh a s a state on

Start-Sleep -Seconds 45

for ($i = 0; $i -lt $LogOut.Length; $i++) {
    $LogOut[$i] = $LogOut[$i].ToString().Split(" ")[5] + ":" + $LogOut[$i].ToString().Split(" ")[7]
}

$LogOut = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "SEND"

$SocketsOut = $LogOut | Select-Object -Unique

$SocketsOut | ForEach-Object {New-NetFirewallRule -DisplayName "$_" -Direction Outbound -Action Allow -LocalPort $_.split(":")[1] -Protocol TCP -Enabled True -Profile Any}