#Hostname and IP
$Hostname = [System.Net.Dns]::GetHostByName($env:computerName) | Select -expand hostname
$IP = Get-NetIPAddress | where AddressFamily -eq 'IPv4' | Select IPAddress | where IPAddress -NotLike '127.0.0.1' | Select -ExpandProperty IPAddress
$OS = (Get-WMIObject win32_operatingsystem).caption
$DNSserver = Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select -expand ifindex) | where ServerAddresses -inotmatch "::" | Select -expand ServerAddresses
$BoardID = Get-TrelloBoard -Name CCDC | Select -Expand id

$Description = "# System Information:
## Operating System: $OS
## Admin User
username: $(whoami)
## Other Details:
###DNS Server(s): $DNSserver"

$ListID = Get-TrelloList -BoardId $BoardID | where name -eq 'Windows' | select -expand id

$CardName = "Hostname [IP]"
$CardName = $CardName -Replace "Hostname", $Hostname
$CardName = $CardName -Replace "IP", $IP
$Card = New-TrelloCard -ListId $ListID -Name $CardName -Description $Description

#Users
$Users = Get-LocalUser | select -expand name
New-TrelloCardComment -Card $Card -Name Users -Comment $Users

#Network Connections
$NetworkConnections = Get-NetTCPConnection -State Listen,Established | where-object {($_.RemotePort -ne 443) -and ($_.LocalPort -ne 5985) -and ($_.LocalAddress -inotmatch '::' )}| sort-object state,localport | select localaddress,localport,remoteaddress,remoteport,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
New-TrelloCardChecklist -Card $Card -Name Connections -Item $NetworkConnections

#Windows Features
$Features = Get-WindowsFeature | Where Installed | select -expand name
New-TrelloCardChecklist -Card $Card -Name Features -Item $Features

#Installed Programs
$Programs = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$Programs = foreach ($obj in $Programs) { if (!($obj.GetValue('DisplayName') -eq $null)) { ($obj.GetValue('DisplayName') + '-' + $obj.GetValue('DisplayVersion')) }}
New-TrelloCardChecklist -Card $Card -Name Programs -Item $Programs

#Conditional for AD
