#Hostname and IP
Write-Host "#### Hostname ####" -ForegroundColor Cyan
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain

Write-Host "#### IP ####" -ForegroundColor Cyan
Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Select-Object IPAddress, InterfaceAlias | Where-Object IPAddress -NotLike '127.0.0.1'

Write-Host "#### Admin ####" -ForegroundColor Cyan
whoami.exe

Write-Host "#### OS ####" -ForegroundColor Cyan
(Get-WMIObject win32_operatingsystem).caption

Write-Host "#### DNS Servers ####" -ForegroundColor Cyan
Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select-Object -expand ifindex) | Where-Object ServerAddresses -inotmatch "::" | Select-Object -expand ServerAddresses

$DC = Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'"
if ($DC) {
    Write-Host "#### DC Detected ####" -ForegroundColor Cyan
}

#Users and Groups
$CommentString = if ($DC) {
    $Groups = Get-AdGroup -Filter 'SamAccountName -NotLike "Domain Users"' | Select-Object -ExpandProperty Name
    $Groups | ForEach-Object {
        $Users = Get-ADGroupMember -Identity $_ | Select-Object -ExpandProperty Name
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Host "Group: $_" 6>&1
            Write-Host "$Users" 6>&1
            
        }
    }
    Write-Host "#### ALL Domain Users ####" -ForegroundColor Cyan
    Get-ADUser -filter * | Select-Object -ExpandProperty Name | Out-String
} else {
    $Groups = net localgroup | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -skip 2
    $Groups = $Groups -replace '\*',''
    $Groups | ForEach-Object {
        # TODO: Test to make sure $_ references correct var
        $Users = net localgroup $_ | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -skip 4
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Host "Group: $_" 6>&1
            Write-Host "$Users" 6>&1
        }
    }
    Write-Host "#### ALL Users ####" -ForegroundColor Cyan
    Get-WmiObject win32_useraccount | ForEach-Object {$_.Name}
}

#Network Connections
#$NetworkConnections = Get-NetTCPConnection -State Listen,Established | where-object {($_.RemotePort -ne 443) -and ($_.LocalPort -ne 5985) -and ($_.LocalAddress -inotmatch '::' )}| sort-object state,localport | Select-Object localaddress,localport,remoteaddress,remoteport,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
#New-TrelloCardChecklist -Card $Card -Name Connections -Item $NetworkConnections

#Windows Features
if(Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2' or ProductType='3'") {
    Get-WindowsOptionalFeature -Online | Where-Object state | Select-Object FeatureName
}

#Installed Programs

Write-Host "#### Installed Programs ####" -ForegroundColor Cyan
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

$InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

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
        Write-Host "[INFO] $item Not Found" -ForegroundColor Yellow
    }
}
New-TrelloCardChecklist -Card $Card -Name RunKeys -Item $Keys.GetEnumerator().MessageData.Message


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