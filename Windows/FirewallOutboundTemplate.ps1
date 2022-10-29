Get-NetFirewallRule -Direction Outbound | Remove-NetFirewallRule

Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 -LogAllowed False -LogFileName "%systemroot%\System32\LogFiles\Firewall\pfirewall.log"

Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block -Enabled True

netsh a s a state off

netsh a s a state on

Start-Sleep -Seconds 45

$LogOut = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "SEND"

$LogOut = $LogOut | ForEach-Object {$_.ToString().Split(" ")[5] | Select-String -Pattern "10.*","192.168.*","172.16.*","172.17.*","172.18.*","172.19.*","172.20.*","172.21.*","172.22.*","172.23.*","172.24.*","172.25.*","172.26.*","172.27.*","172.28.*","172.29.*","172.30.*","172.31.*"}

for ($i = 0; $i -lt $LogOut.Length; $i++) {
    $LogOut[$i] = $LogOut[$i].ToString().Split(" ")[5] + ":" + $LogOut[$i].ToString().Split(" ")[7]
}

$SocketsOut = $LogOut | Select-Object -Unique

$SocketsOut | ForEach-Object {New-NetFirewallRule -DisplayName "$_" -Direction Outbound -Action Allow -RemotePort $_.split(":")[1] -RemoteAddress $_.split(":")[0] -Protocol TCP -Enabled True -Profile Any}