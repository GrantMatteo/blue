[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module PowerTrello -Confirm:$false -Force
$TrelloAPI = Read-Host -Prompt "Trello API Key (https://trello.com/app-key)"
$TrelloAccessToken = Read-Host -Prompt "Trello Access Token"


wget https://github.com/evanjd711/PowershellProjects/archive/refs/heads/main.zip -UseBasicParsing -OutFile $env:ProgramFiles\Trello.zip
Expand-Archive $env:ProgramFiles\Trello.zip -DestinationPath $env:ProgramFiles\Trello\
$TrelloPath = "$env:ProgramFiles\Trello\PowershellProjects-main\TrelloAutomation\"

$Hostname = [System.Net.Dns]::GetHostByName($env:computerName) | Select -expand hostname
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
$Denied = @()
foreach ($Computer in $Computers) {
    try {
        Copy-Item -Path $TrelloPath -Destination "$env:ProgramFiles" -toSession (New-PSSession -ComputerName $Computer) -Recurse -Force
    }
    catch {
        $Denied += $Computer
    }
}

$WinRMable = Compare-Object $Computers $Denied | Select -ExpandProperty InputObject

Set-TrelloConfiguration -AccessToken $TrelloAccessToken -ApiKey $TrelloAPI
$Board = New-TrelloBoard -Name CCDC
$BoardID = Get-TrelloBoard -Name CCDC | Select -Expand id

#Create Lists
$IncomingTicketsList = New-TrelloList -BoardID $BoardID -Name 'Incoming Tickets' -Position 1 | Select -expand id
$ResolvedTicketsList = New-TrelloList -BoardID $BoardID -Name 'Resolved Tickets' -Position 2 | Select -expand id
$LinuxList = New-TrelloList -BoardID $BoardID -Name 'Linux' -Position 3 | Select -expand id
$WindowsList = New-TrelloList -BoardID $BoardID -Name 'Windows' -Position 4 | Select -expand id
$NetworkingList = New-TrelloList -BoardID $BoardID -Name 'Networking' -Position 5 | Select -expand id
$BusinessList = New-TrelloList -BoardID $BoardID -Name 'Business' -Position 6 | Select -expand id

#Create Cards for Incoming Tickets
$BoxTemplateCard = New-TrelloCard -ListId $IncomingTicketsList -Name 'Box Template [DO NOT TOUCH]'
$ManualWork = New-TrelloCard -ListId $WindowsList -Name "Rejected Windows Boxes"
New-TrelloCardChecklist -Card $ManualWork -Name Hosts -Item $Denied
New-TrelloCardChecklist -Card $BoxTemplateCard -Name Baselining -Item @('Inventory', 'Change Default Passwords', 'Configure Log Forwarding')

Invoke-Command $WinRMable -ScriptBlock {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module PowerTrello -Scope AllUsers -Confirm:$false -Force
    Set-TrelloConfiguration -ApiKey $Using:TrelloAPI -AccessToken $Using:TrelloAccessToken -ErrorAction SilentlyContinue
    Sleep 15
    New-HostCard -BoardID $Using:BoardID -System 'Windows' -User 'Tanay'
}
