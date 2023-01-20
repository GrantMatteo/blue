[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module PowerTrello -Confirm:$false -Force
$TrelloAPI = Read-Host -Prompt "Trello API Key (https://trello.com/app-key)"
$TrelloAccessToken = Read-Host -Prompt "Trello Access Token"



Invoke-WebRequest https://live.sysinternals.com/Sysmon.exe -UseBasicParsing -OutFile C:\Windows\System32\Sysmon.exe
Invoke-WebRequest https://live.sysinternals.com/procexp.exe -UseBasicParsing -OutFile C:\Windows\System32\procexp.exe
Invoke-WebRequest https://live.sysinternals.com/Autoruns.exe -UseBasicParsing -OutFile C:\Windows\System32\Autoruns.exe
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -UseBasicParsing -OutFile C:\Windows\System32\smce.xml
$Stigs = "$env:ProgramFiles\blue\blue-main\Windows\stigs.inf"
$Sysmon = "C:\Windows\System32\Sysmon.exe"
$Procexp = "C:\Windows\System32\procexp.exe"
$Autoruns = "C:\Windows\System32\Autoruns.exe"
$SysmonConfig = "C:\Windows\System32\smce.xml"
$FirewallIn = "$env:ProgramFiles\blue\Windows\Firewall\FirewallInboundTemplate.ps1"
$FirewallOut = "$env:ProgramFiles\blue\Windows\Firewall\FirewallOutboundTemplate.ps1"

Get-ChildItem $env:ProgramFiles\blue\Windows -Recurse | Unblock-File

#$Hostname = [System.Net.Dns]::GetHostByName($env:computerName) | Select -expand hostname
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
$Denied = @()
foreach ($Computer in $Computers) {
    try {
        $Session = New-PSSession -ComputerName $Computer
        Copy-Item -Path $Stigs -Destination "C:\Windows\System32\stigs.inf" -toSession $Session -Recurse -Force
        Copy-Item -Path $Sysmon -Destination "C:\Windows\System32\Sysmon.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $Procexp -Destination "C:\Windows\System32\procexp.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $Autoruns -Destination "C:\Windows\System32\Autoruns.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $SysmonConfig -Destination "C:\Windows\System32\smce.xml" -toSession $Session -Recurse -Force
        Copy-Item -Path $FirewallIn -Destination "C:\Windows\System32\FirewallInboundTemplate.ps1" -toSession $Session -Recurse -Force
        Copy-Item -Path $FirewallOut -Destination "C:\Windows\System32\FirewallOutboundTemplate.ps1" -toSession $Session -Recurse -Force
    }
    catch {
        $Denied += $Computer
        Write-Host "Failed to copy to $Computer" -ForegroundColor Red
    }
}

# $WinRMable = Compare-Object $Computers $Denied | Select-Object -ExpandProperty InputObject

Set-TrelloConfiguration -AccessToken $TrelloAccessToken -ApiKey $TrelloAPI
New-TrelloBoard -Name CCDC
$BoardID = Get-TrelloBoard -Name CCDC | Select-Object -Expand id

#Create Lists
$IncomingTicketsList = New-TrelloList -BoardID $BoardID -Name 'Incoming Tickets' -Position 1 | Select-Object -expand id
New-TrelloList -BoardID $BoardID -Name 'Resolved Tickets' -Position 2 | Select-Object -expand id
New-TrelloList -BoardID $BoardID -Name 'Linux' -Position 3 | Select-Object -expand id
$WindowsList = New-TrelloList -BoardID $BoardID -Name 'Windows' -Position 4 | Select-Object -expand id
New-TrelloList -BoardID $BoardID -Name 'Networking' -Position 5 | Select-Object -expand id
New-TrelloList -BoardID $BoardID -Name 'Business' -Position 6 | Select-Object -expand id

#Create Cards for Incoming Tickets
$BoxTemplateCard = New-TrelloCard -ListId $IncomingTicketsList -Name 'Box Template [DO NOT TOUCH]'
$ManualWork = New-TrelloCard -ListId $WindowsList -Name "Rejected Windows Boxes"
New-TrelloCardChecklist -Card $ManualWork -Name Hosts -Item $Denied
New-TrelloCardChecklist -Card $BoxTemplateCard -Name Baselining -Item @('Inventory', 'Change Default Passwords', 'Configure Log Forwarding')

#Invoke-Command $WinRMable -ScriptBlock {
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #Install-Module PowerTrello -Scope AllUsers -Confirm:$false -Force
    #Set-TrelloConfiguration -ApiKey $Using:TrelloAPI -AccessToken $Using:TrelloAccessToken
    #New-HostCard -BoardID $Using:BoardID -System 'Windows' -User 'Tanay'
#}
#test