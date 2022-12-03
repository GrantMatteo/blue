param(
    [string] $p,
    [string] $p2
)

#Hostname and IP
$Hostname = hostname
$IP = Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Select-Object IPAddress | Where-Object IPAddress -NotLike '127.0.0.1' | Select-Object -ExpandProperty IPAddress
$OS = (Get-WMIObject win32_operatingsystem).caption
$DNSserver = Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select-Object -expand ifindex) | Where-Object ServerAddresses -inotmatch "::" | Select-Object -expand ServerAddresses
$BoardID = Get-TrelloBoard -Name CCDC | Select-Object -Expand id

$Description = "# System Information:
## Operating System: $OS
## Admin User
username: $(whoami)
## Other Details:
###DNS Server(s): $DNSserver"

$ListID = Get-TrelloList -BoardId $BoardID | Where-Object name -eq 'Windows' | Select-Object -expand id

$CardName = "Hostname [IP]"
$CardName = $CardName -Replace "Hostname", $Hostname
$CardName = $CardName -Replace "IP", $IP
$Card = New-TrelloCard -Name $CardName -Description $Description -ListId $ListID


#Users and Groups
$CommentString = if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    $Groups = Get-AdGroup -Filter 'SamAccountName -NotLike "Domain Users" -and SamAccountName -NotLike "Domain Admins"' | Select-Object -ExpandProperty Name
    $Groups | ForEach-Object {
        $Users = Get-ADGroupMember -Identity $_ | Select-Object -ExpandProperty Name
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Host "**Group: $_**" 6>&1
            Write-Host "$Users" 6>&1
            
        }
    }
    $Users = Get-ADUser -filter * | Select-Object -ExpandProperty Name | Out-String
} else {
    $Groups = Get-LocalGroup | Select-Object -ExpandProperty name
    $Groups | ForEach-Object {
        $Users = Get-LocalGroupMember -Name $_ | Select-Object -ExpandProperty name
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Host "**Group: $_**" 6>&1
            Write-Host "$Users" 6>&1
        }
    }
    $Users = Get-LocalUser | Select-Object -expand name | Out-String
}

New-TrelloCardComment -Card $Card -Comment $Users
New-TrelloCardComment -Card $Card -Comment ($CommentString | Out-String)
New-TrelloCardComment -Card $Card -Comment "Password: $p"
New-TrelloCardComment -Card $Card -Comment "deaters: $p2"

#Network Connections
#$NetworkConnections = Get-NetTCPConnection -State Listen,Established | where-object {($_.RemotePort -ne 443) -and ($_.LocalPort -ne 5985) -and ($_.LocalAddress -inotmatch '::' )}| sort-object state,localport | Select-Object localaddress,localport,remoteaddress,remoteport,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
#New-TrelloCardChecklist -Card $Card -Name Connections -Item $NetworkConnections

#Windows Features
if(Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2' or ProductType='3'") {
    $Features = Get-WindowsFeature | Where-Object Installed | Select-Object -expand name | Out-String
    New-TrelloCardComment -Card $Card -Comment $Features
}

#Installed Programs
$Programs = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$Programs = foreach ($obj in $Programs) { 
    if (($null -NE $obj.GetValue('DisplayName')) -and ($obj.GetValue('DisplayName') -notlike "*Microsoft Visual C++*")) { 
        $obj.GetValue('DisplayName') + '-' + $obj.GetValue('DisplayVersion')
    }
}
New-TrelloCardChecklist -Card $Card -Name Programs -Item $Programs

Start-Sleep -Seconds 10

#RunKeys
$regPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", 
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
            "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell", 
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells", 
            "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components", 
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", 
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", 
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices", 
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices", 
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", 
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", 
            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows")
$Keys = foreach ($item in $regPath) {
    try{
        $reg = Get-ItemProperty -Path $item -ErrorAction Stop
        Write-Host "[Startups: Registry Path] **$item**" -ForegroundColor Green 6>&1
        $reg | Get-Member -MemberType NoteProperty -ErrorAction Stop | Select-Object -Expand Name | ForEach-Object {
            if ($_.StartsWith("PS") -or $_.StartsWith("VM")) {
                # Write-Host "[Startups: Registry Values] Default value detected"
            }
            else {
                Write-Host "[$_] $($reg.$_)" -ForegroundColor Yellow 6>&1
            }
        }
    }
    catch{
        Write-Host "**[$item]** No Values Found" -ForegroundColor Red
    }
}
New-TrelloCardChecklist -Card $Card -Name RunKeys -Item $Keys.GetEnumerator().MessageData.Message

Start-Sleep -Seconds 10

#Scheduled Tasks
$tasks = Get-ScheduledTask | Where-Object { $_.Author -like '*\*' -and $_.Author -notlike '*.exe*' -and $_.Author -notlike '*.dll*' } 
$TaskOut = foreach ($task in $tasks) {
    $author = $task.Author
    $taskname = $task.TaskName
    $taskpath = $task.TaskPath
    $taskfile = (Get-ScheduledTask $taskname).actions.Execute
    $taskargs = (Get-ScheduledTask $taskname).actions.Arguments
    Write-Host "[Startups: Scheduled Task] Path: "**$taskpath$taskname**" Author: "$author" Running file: "**$taskfile**" Arguments: "**$taskargs**"" -ForegroundColor Yellow 6>&1
}
if ( $null -eq $tasks ) {
    $TaskOut = Write-Host "[Startups: Scheduled Tasks] No tasks detected..." -ForegroundColor Red 6>&1
    New-TrelloCardChecklist -Card $Card -Name ScheduledTasks -Item $TaskOut.MessageData.Message
} else {
New-TrelloCardChecklist -Card $Card -Name ScheduledTasks -Item $TaskOut.GetEnumerator().MessageData.Message
}

#SMB Shares
$Shares = Get-WmiObject -Class Win32_Share | Select-Object -ExpandProperty Name,Path | Out-String
New-TrelloCardComment -Card $Card -Comment $Shares