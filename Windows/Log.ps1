$Error.Clear()
$ErrorActionPreference = "Continue"

Write-Output "#########################"
Write-Output "#    Hostname/Domain    #"
Write-Output "#########################"
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
Write-Output "#########################"
Write-Output "#          IP           #"
Write-Output "#########################"
(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'") | % {$_.Description + "`n" + $_.Ipaddress + "`n"}

######### Logging#########
# Include command line in process creation events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f | Out-Null
# Powershell command transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f | Out-Null
# Powershell script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f | Out-Null
Write-Output "$Env:ComputerName [INFO] Powershell Logging enabled"
C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False
Write-Output "$Env:ComputerName [INFO] IIS Logging enabled"

######### Sysmon Setup #########
if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    & "C:\Windows\System32\bins\Sysmon64.exe" -accepteula -i C:\Windows\System32\bins\smce.xml
}
else {
    & "C:\Windows\System32\bins\Sysmon.exe" -accepteula -i C:\Windows\System32\bins\smce.xml
}
Write-Output "$Env:ComputerName [INFO] Sysmon installed and configured" 