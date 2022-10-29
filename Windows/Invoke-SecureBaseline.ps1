function Invoke-SecureBaseline {

    Param([switch]$pre2008)
    Param([switch]$2008r2)

    $OS = (Get-WMIObject win32_operatingsystem).caption
    if ($OS -notmatch "Vista|vista|2008|2003|XP|xp|7") {
        $Error.Clear()
        $ErrorActionPreference = "SilentlyContinue"
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
        if (!$oldaf -or $2008r2) {
            # Deny all NTLM authentication in the domain
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNTLMInDomain" -Value 7
            # Deny all inbound and outbound NTLM + audit attempts
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 2
        }
        # Disable storage of plaintext creds in WDigest
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
        # Enable remote UAC for Local accounts
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0
        # Enable LSASS Protection
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
        # Enable LSASSS process auditing
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Name "LSASS.exe"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8
        ######### Defender #########
        #TODO: Hardcode all defender defaults

        # Block Office applications from injecting code into other processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
        # Block Office applications from creating executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
        # Block all Office applications from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
        # Block JavaScript or VBScript from launching downloaded executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
        # Block execution of potentially obfuscated scripts
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
        # Block executable content from email client and webmail
        Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
        # Block Win32 API calls from Office macro
        Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
        # Block process creations originating from PSExec and WMI commands
        Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
        # Block untrusted and unsigned processes that run from USB
        Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
        # Use advanced protection against ransomware
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
        # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
        Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
        # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
        # Block Office communication application from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
        # Block Adobe Reader from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
        # Block persistence through WMI event subscription
        Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
        ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
            Remove-MpPreference -ExclusionExtension $ExcludedExt
        }
        ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
            Remove-MpPreference -ExclusionIpAddress $ExcludedIp
        }
        ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
            Remove-MpPreference -ExclusionPath $ExcludedDir
        }
        ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
            Remove-MpPreference -ExclusionProcess $ExcludedProc
        }
        ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR
        }
        ######### Disable PHP Functions #########
        $php = Get-ChildItem C:\ php.exe -recurse -ErrorAction SilentlyContinue | ForEach-Object {& $_.FullName --ini | Out-String}
        $ConfigFiles
        ForEach($OutputLine in $($php -split "`r`n")) {
            if ($OutputLine -match 'Loaded') {
                ForEach-Object {
                    $ConfigFiles = $ConfigFiles + ($OutputLine -split "\s{9}")[1]
                }
            }
        }
        $ConfigString = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,
        curl_multi_exec,parse_ini_file,show_source
        file_uploads=off"
        Foreach ($ConfigFile in $ConfigFiles) {
            Add-Content $ConfigFile $ConfigString
        }

        ######### User Rights Assignment #########

        ######### Service Lockdown #########
        if ($DC) {
            Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
            # CVE-2020-1472 (Zerologon)
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force
            # CVE-2021-42278 & CVE-2021-42287 (noPac)
            Set-ADDomain -Identity $Domain -Replace @{"ms-DS-MachineAccountQuota"="0"}
            # TODO: Domain Member: Digitally encrypt or sign secure channel data (always) - Enabled works 2008
            if ($2008r2) {
                # Domain controller: LDAP server signing requirements
                reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f
                # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before supposedly)
                # TODO: Test below for 2008r2 
                reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f
            }
            elseif ($oldaf) {
                # Domain controller: LDAP server signing requirements
                reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 1 /f
                # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before)
                reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f
            }
            else {
                # Domain controller: LDAP server signing requirements
                reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f
                # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before)
                reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f
            }
            
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
        reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
        ######### Logging#########
        # Powershell command transcription
        reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f
        # Powershell script block logging
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f


        ######### Constrained Language Mode #########
        [System.Environment]::SetEnvironmentVariable('__PSLockDownPolicy','4','Machine')

        ######### Sysmon Setup #########
        Set-Location $HOME\Downloads
        Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -Outfile Sysmon.exe
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -Outfile sysmonconfig-export.xml
        .\sysmon.exe -accepteula -i sysmonconfig-export.xml

        $Error | Out-File $HOME\Documents\isb.txt -Append -Encoding utf8
    }
    else {
        # Write 2008 earlier os configs here
    }
}
