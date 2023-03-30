$ErrorActionPreference = "Continue"

$Stigs = "$env:ProgramFiles\blue-main\Windows\bins\stigs.inf"
$Sysmon64 = "$env:ProgramFiles\blue-main\Windows\bins\Sysmon64.exe"
$Sysmon = "$env:ProgramFiles\blue-main\Windows\bins\Sysmon.exe"
$Procexp = "$env:ProgramFiles\blue-main\Windows\bins\procexp.exe"
$Autoruns = "$env:ProgramFiles\blue-main\Windows\bins\Autoruns.exe"
$SysmonConfig = "$env:ProgramFiles\blue-main\Windows\bins\smce.xml"
$SleepBeacon = "$env:ProgramFiles\blue-main\Windows\bins\Hunt-Sleeping-Beacons.exe"
$StopThread = "$env:ProgramFiles\blue-main\Windows\bins\Stop-Thread.ps1"
$FirewallIn = "$env:ProgramFiles\blue-main\Windows\bins\FirewallInboundTemplate.ps1"
$FirewallOut = "$env:ProgramFiles\blue-main\Windows\bins\FirewallOutboundTemplate.ps1"

Copy-Item -Path $Stigs -Destination "C:\Windows\System32\bins\stigs.inf" -Recurse -Force
Copy-Item -Path $Sysmon64 -Destination "C:\Windows\System32\bins\Sysmon64.exe" -Recurse -Force
Copy-Item -Path $Sysmon -Destination "C:\Windows\System32\bins\Sysmon.exe" -Recurse -Force
Copy-Item -Path $Procexp -Destination "C:\Windows\System32\bins\procexp.exe" -Recurse -Force
Copy-Item -Path $Autoruns -Destination "C:\Windows\System32\bins\Autoruns.exe" -Recurse -Force
Copy-Item -Path $SysmonConfig -Destination "C:\Windows\System32\bins\smce.xml" -Recurse -Force
Copy-Item -Path $SleepBeacon -Destination "C:\Windows\System32\bins\Hunt-Sleeping-Beacons.exe" -Recurse -Force
Copy-Item -Path $StopThread -Destination "C:\Windows\System32\bins\Stop-Thread.ps1" -Recurse -Force
Copy-Item -Path $FirewallIn -Destination "C:\Windows\System32\bins\FirewallInboundTemplate.ps1" -Recurse -Force
Copy-Item -Path $FirewallOut -Destination "C:\Windows\System32\bins\FirewallOutboundTemplate.ps1" -Recurse -Force

Get-ChildItem $env:ProgramFiles\blue-main\Windows -Recurse | Unblock-File

#$Hostname = [System.Net.Dns]::GetHostByName($env:computerName) | Select -expand hostname
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty Name
$Localhost = hostname

foreach ($Computer in $Computers) {
    if (!($Computer -eq $Localhost)) {
        Write-Host "[INFO] Preparing to WinRM to: $Computer" -ForegroundColor Green
        Robocopy.exe $env:ProgramFiles\blue-main\Windows\bins \\$Computer\ADMIN$\System32\bins
        <#
        Copy-Item -Path $Stigs -Destination "C:\Windows\System32\stigs.inf" -toSession $Session -Recurse -Force
        Copy-Item -Path $Sysmon64 -Destination "C:\Windows\System32\Sysmon64.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $Sysmon -Destination "C:\Windows\System32\Sysmon.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $Procexp -Destination "C:\Windows\System32\procexp.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $Autoruns -Destination "C:\Windows\System32\Autoruns.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $SysmonConfig -Destination "C:\Windows\System32\smce.xml" -toSession $Session -Recurse -Force
        Copy-Item -Path $SleepBeacon -Destination "C:\Windows\System32\Hunt-Sleeping-Beacons.exe" -toSession $Session -Recurse -Force
        Copy-Item -Path $FirewallIn -Destination "C:\Windows\System32\FirewallInboundTemplate.ps1" -toSession $Session -Recurse -Force
        Copy-Item -Path $FirewallOut -Destination "C:\Windows\System32\FirewallOutboundTemplate.ps1" -toSession $Session -Recurse -Force
        #>
    }
    else {
        Write-Host "[ERROR] Failed to copy to $Computer" -ForegroundColor Red
    }
}