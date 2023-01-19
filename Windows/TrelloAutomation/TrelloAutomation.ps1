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
if ($DC) {
    $Groups = Get-AdGroup -Filter 'SamAccountName -NotLike "Domain Users"' | Select-Object -ExpandProperty Name
    $Groups | ForEach-Object {
        $Users = Get-ADGroupMember -Identity $_ | Select-Object -ExpandProperty Name
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Host "Group: $_"
            Write-Host "$Users"
            
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
            Write-Host "Group: $_"
            Write-Host "$Users"
        }
    }
    Write-Host "#### ALL Users ####" -ForegroundColor Cyan
    Get-WmiObject win32_useraccount | ForEach-Object {$_.Name}
}

#Network Connections
#$NetworkConnections = Get-NetTCPConnection -State Listen,Established | where-object {($_.RemotePort -ne 443) -and ($_.LocalPort -ne 5985) -and ($_.LocalAddress -inotmatch '::' )}| sort-object state,localport | Select-Object localaddress,localport,remoteaddress,remoteport,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
#New-TrelloCardChecklist -Card $Card -Name Connections -Item $NetworkConnections

#Windows Features
Write-Host "#### Features ####" -ForegroundColor Cyan
Get-WindowsOptionalFeature -Online | Where-Object state | Select-Object FeatureName

#Installed Programs

Write-Host "#### Installed Programs ####" -ForegroundColor Cyan
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

$InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

#RunKeys
Write-Host "#### Registry Startups ####" -ForegroundColor Cyan
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
foreach ($item in $regPath) {
    try{
        $reg = Get-ItemProperty -Path $item -ErrorAction SilentlyContinue
        Write-Host "[Registry Startups] $item" -ForegroundColor Cyan 
        $reg | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -Expand Name | ForEach-Object {
            if ($_.StartsWith("PS") -or $_.StartsWith("VM")) {
                # Write-Host "[Startups: Registry Values] Default value detected"
            }
            else {
                Write-Host "[$_] $($reg.$_)" -ForegroundColor Cyan
            }
        }
    }
    catch{
        Write-Host "[Registry Startup] $item Not Found" -ForegroundColor Yellow
    }
}



#Scheduled Tasks
Write-Host "#### Scheduled Tasks ####" -ForegroundColor Cyan
$tasks = Get-ScheduledTask | Where-Object { $_.Author -like '*\*' -and $_.Author -notlike '*.exe*' -and $_.Author -notlike '*.dll*' } 
foreach ($task in $tasks) {
    $author = $task.Author
    $taskname = $task.TaskName
    $taskpath = $task.TaskPath
    $taskfile = (Get-ScheduledTask $taskname).actions.Execute
    $taskargs = (Get-ScheduledTask $taskname).actions.Arguments
    Write-Host "[Scheduled Task] Path: "$taskpath$taskname" Author: "$author" Running file: "$taskfile" Arguments: "$taskargs"" -ForegroundColor Cyan
}

#SMB Shares
Write-Host "#### SMB Shares ####" -ForegroundColor Cyan
Get-WmiObject -Class Win32_Share | Select-Object Name,Path