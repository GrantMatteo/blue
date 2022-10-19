function Invoke-SecureBaseline {
    $DC = $false
    if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
        $DC = $true
        Import-Module ActiveDirectory
    }
    $IIS = $false
    if (Get-Service -Name W3SVC) {
        $IIS = $true
        Import-Module WebAdministration
    }
    
    $Hostname = [System.Net.Dns]::GetHostByName($env:computerName) | Select-Object -expand hostname
    $IP = Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Select-Object IPAddress | Where-Object IPAddress -NotLike '127.0.0.1' | Select-Object -ExpandProperty IPAddress
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module PowerTrello -Force -Confirm:$false

######### SMB #########
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

######### Reset Policies #########
    Copy-Item C:\Windows\System32\GroupPolicy* C:\gp -Recurse 
    Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force
    gpupdate /force

######### Passwords #########
    # TODO: Generate CSV of Users for PCR
    # Add neccesary framework
    Add-Type -AssemblyName System.web

    # Generate a 12 character string with 3 alphanumeric characters
    $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
    while ($p -match '[,;:|iIlLoO0]') {
        $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
    }
    $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
    while ($p2 -match '[,;:|iIlLoO0]') {
        $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
    }
    
    Get-WmiObject -class win32_useraccount | Where-object {$_.name -ne "krbtgt"} | ForEach-Object {net user $_.name $p > $null}
    $Board = Get-TrelloBoard -Name "CCDC"
    $CardName = "Hostname [IP]"
    $CardName = $CardName -Replace "Hostname", $Hostname
    $CardName = $CardName -Replace "IP", $IP 
    $Card = Get-TrelloCard -Card (Get-TrelloCard -Board $Board -Name $CardName)
    New-TrelloCardComment -Card $Card -Name -Comment "Password: $p"
    net user deaters $p2 /add
    New-TrelloCardComment -Card $Card -Name -Comment "deaters: $p2"
    if ($DC) {
        $SchemaAdmin = (Get-ADGroupMember -Identity "Domain Admins").name
        Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
            if ($SchemaAdmin -notcontains $_.name) {
                Remove-ADGroupMember -Identity "Domain Admins" -Members $_.name -confirm:$false
            }
        }
        Add-ADGroupMember -Identity "Domain Admins" -Members "deaters"
    }
    else {
        Get-WmiObject -class win32_useraccount | ForEach-Object {net localgroup administrators $_.name /delete}
        net localgroup administrators deaters /add
    }
    
    
    
######### PTH Mitigation #########
    # Disable NTLM 
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

    $ConfigString = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,
    curl_multi_exec,parse_ini_file,show_source
    file_uploads=off"

    $file = Get-ChildItem C:\ php.ini -recurse | Foreach-Object {$_.fullname}

    Add-Content $file $ConfigString

######### User Rights Assignment #########

######### Sysmon Setup #########
    Set-Location $HOME\Downloads
    Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -Outfile Sysmon.exe
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -Outfile sysmonconfig-export.xml
    .\sysmon.exe -accepteula -i sysmonconfig-export.xml

######### Service Lockdown #########
    if ($DC) {
        Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
        # CVE-2020-1472 (Zerologon)
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force
        # CVE-2021-42278 & CVE-2021-42287 (noPac)
        Set-ADDomain -Identity $Domain -Replace @{"ms-DS-MachineAccountQuota"="0"}
        # Domain controller: LDAP server signing requirements
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f
        # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before)
        reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f
    }

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
    Stop-Service -Name Spooler -Force
    Set-Service -Name Spooler -StartupType Disabled

######### Misc #########
    # CVE-2021-34527 (PrintNightmare)
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f
    # Network security: LDAP client signing requirements
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f
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

######### Constrained Language Mode #########
[System.Environment]::SetEnvironmentVariable('__PSLockDownPolicy','4','Machine')
