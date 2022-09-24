function Invoke-SecureBaseline {
    $DC = $false
    if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
        $DC = $true
    }
    $IIS = $false
    if (Get-Service -Name W3SVC) {
        $IIS = $true
        Import-Module WebAdministration
    }
######### SMB #########
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

######### Reset Policies #########
    Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force
    gpupdate /force

######### Passwords #########
    # TODO: Generate CSV of Users for PCR
    # Add neccesary framework
    Add-Type -AssemblyName System.web

    # Generate a 12 character string with 3 alphanumeric characters
    $p = [System.Web.Security.Membership]::GeneratePassword(14,4)

    # Get all user account wmi objects and set their passwords with net user
    # TODO: Send $p to Trello
    Get-WmiObject -class win32_useraccount | ForEach-Object {net user $_.name $p > $null}

######### PTH Mitigation #########
    # Disable NTLM Authentication 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -Value 1
    # Deny all NTLM authentication in the domain
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNTLMInDomain" -Value 7
    # Deny all inbound and outbound NTLM + audit attempts
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 2
    # Disable storage of plaintext creds in WDigest
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
    # Enable remote UAC for Local accounts
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0
    # Enable LSASS Protection
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
    # Enable LSASSS process auditing
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Name "LSASS.exe"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8

######### Disable PHP Functions #########


######### User Rights Assignment #########

######### Sysmon Setup #########
    Set-Location $HOME\Downloads
    Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -Outfile Sysmon.exe
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -Outfile sysmonconfig-export.xml
    .\sysmon.exe -accepteula -i sysmonconfig-export.xml

######### Service Lockdown #########
    if ($DC) {Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"}

    if ($IIS) {
        foreach ($app in (Get-ChildItem IIS:\AppPools)) {
            Set-ItemProperty -Path "IIS:\AppPools\$($app.name)" -name processModel.identityType -value 4
        }
        foreach ($site in (Get-ChildItem IIS:\Sites)) {
            Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath $site.PSPath -value False
            Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $site.name -filter "system.webServer/serverRuntime" -name "authenticatedUserOverride" -value "UseAuthenticatedUser"
            Set-WebConfigurationProperty -pspath $site.PSPath -filter "system.webServer/serverRuntime" -name "authenticatedUserOverride" -value "UseAuthenticatedUser" -ErrorAction SilentlyContinue
        }
    }

######### Constrained Language Mode #########
    [System.Environment]::SetEnvironmentVariable('__PSLockDownPolicy','4','Machine')

######### Logging#########
    # Powershell command transcription
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "PowerShell"
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "Transcription"
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ScriptBlockLogging"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -PropertyType "String" -Value "C:\Windows\debug\timber"
    # Powershell script block logging
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

}
