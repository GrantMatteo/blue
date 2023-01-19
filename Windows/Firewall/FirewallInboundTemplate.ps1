netsh advfirewall state allprofiles state off
netsh advfirewall firewall delete rule all
netsh 

netsh advfirewall set allprofiles logging filename %systemroot%\System32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 16384
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy "blockinboundalways,allowoutbound"
netsh advfirewall firewall add rule name="RDP" dir=in action=allow program="$env:SystemRoot\system32\svchost.exe" service="TermService" enable=yes profile=any localport=3389 protocol=tcp
netsh advfirewall firewall add rule name="SSH" dir=in action=allow enable=yes profile=any localport=22 protocol=tcp
netsh advfirewall firewall add rule name="WinRM" dir=in action=allow enable=yes profile=any localport=5985 protocol=tcp remoteip=localsubnet


netsh a s a state off

netsh a s a state on

#Start-Sleep -Seconds 30

$LogIn = Get-Content "$Env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" | Select-String -Pattern "DROP TCP" | Select-String -Pattern "RECEIVE"

for ($i = 0; $i -lt $LogIn.Length; $i++) {$LogIn[$i] = $LogIn[$i].ToString().Split(" ")[5] + ":" + $LogIn[$i].ToString().Split(" ")[7]}

$SocketsIn = $LogIn | Select-Object -Unique

$SocketsIn | ForEach-Object {
    if($PortTable[[uint16] $_.split(":")[1]] -eq $NULL) {
        netsh advfirewall firewall add rule name= "$_" dir=in action=allow protocol=TCP localport= $_.split(":")[1] enable=yes
    } else {
        $Program = $_.split(":")[1];
        $Program = ($PortTable.GetEnumerator() | Where-Object key -eq $Program | Select-Object -expand Value)
        netsh advfirewall firewall add rule name= "$_" program= $Program dir=in action=allow protocol=TCP localport= $_.split(":")[1] enable=yes
    }
}
