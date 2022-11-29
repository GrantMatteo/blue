function Invoke-SecureBaseline {

    Param([switch]$Pre2008OnPrem)
    Param([switch]$2008r2OnPrem)

    $OS = (Get-WMIObject win32_operatingsystem).caption
    # TODO: Remove
    if ($OS -notmatch "ista|2008|2003|XP|xp|Xp|7") {
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

        ######### SMB #########
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
        reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
        reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
        net share C$ /delete
        if (!$DC) {
            # TODO: see if this automatically removes shares
            reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
            reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
        }
        ######### Reset Policies #########
        Copy-Item C:\Windows\System32\GroupPolicy* C:\gp -Recurse 
        Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force
        gpupdate /force

        ######### Passwords #########
        # TODO: Generate CSV of Users for PCR
        # Add neccesary framework
        Add-Type -AssemblyName System.Web

        # Generate a 12 character string with 3 alphanumeric characters
        $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
        while ($p -match '[,;:|iIlLoO0]') {
            $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
        }
        $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
        while ($p2 -match '[,;:|iIlLoO0]') {
            $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
        }


        if ($DC) {
            Get-WmiObject -class win32_useraccount | Where-object {$_.name -ne "krbtgt"} | ForEach-Object {net user $_.name $p > $null}
            net user deaters $p2 /add
            Get-ADUser -Filter * | Set-ADUser -AllowReversiblePasswordEncryption 0 -PasswordNotRequired 0
            $SchemaAdmin = (Get-ADGroupMember -Identity "Domain Admins").name
            Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
                if ($SchemaAdmin -notcontains $_.name) {
                    Remove-ADGroupMember -Identity "Domain Admins" -Members $_.name -confirm:$false
                }
            }
            Add-ADGroupMember -Identity "Domain Admins" -Members "deaters"
            
        }
        else {
            Get-WmiObject -class win32_useraccount | ForEach-Object {net user $_.name $p > $null}
            net user deaters $p2 /add
            Get-WmiObject -class win32_useraccount | ForEach-Object {net localgroup administrators $_.name /delete}
            net localgroup administrators deaters /add
        }
        
        powershell.exe -file "$env:ProgramFiles\TrelloAutomation\TrelloAutomation.ps1" -p $p -p2 $p2

        # TODO: PasswordNotRequired $false
        ######### PTH Mitigation #########
        # Disable storage of the LM hash for passwords less than 15 characters
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f
        # Network security: LAN Manager authentication level
        # Do not send LM or NTLM responses, only NTLMv2
        # https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
        
        if (!$Pre2008OnPrem -and !$2008r2OnPrem) {
            # Deny all NTLM authentication in the domain
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RestrictNTLMInDomain /t REG_DWORD /d 7 /f
            # Deny all inbound and outbound NTLM + audit attempts
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d 2 /f
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d 2 /f
        }
        # Disable storage of plaintext creds in WDigest
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
        # Enable remote UAC for Local accounts
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
        # Enable LSASS Protection
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
        # Enable LSASSS process auditing
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f
        ######### Defender #########
        #TODO: Hardcode all defender defaults

        reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f
        reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 1 /f
        reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f
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
        $ConfigString = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
        file_uploads=off"
        Foreach ($ConfigFile in $ConfigFiles) {
            Add-Content $ConfigFile $ConfigString
        }

        ######### User Rights Assignment #########
        # TODO import file
        (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/cpp-cyber/blue/main/Windows/stigs.inf',"$Home\Downloads\stigs.inf")
        Write-Output Y | Secedit /configure /db secedit.sdb /cfg "$Home\Downloads\stigs.inf" /overwrite
        ######### Service Lockdown #########
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d 1 /f
        if ($DC) {
            Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
            # CVE-2020-1472 (Zerologon)
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force
            # CVE-2021-42278 & CVE-2021-42287 (noPac)
            Set-ADDomain -Identity $Domain -Replace @{"ms-DS-MachineAccountQuota"="0"}
            # TODO: Domain Member: Digitally encrypt or sign secure channel data (always) - Enabled works 2008
            if ($2008r2OnPrem) {
                # Domain controller: LDAP server signing requirements
                reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f
                # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before supposedly)
                # TODO: Test below for 2008r2 
                reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f
            }
            elseif ($Pre2008OnPrem) {
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
                # TODO: Change to appcmd
                Set-ItemProperty -Path "IIS:\AppPools\$($app.name)" -name processModel.identityType -value 4
            }
            foreach ($site in (Get-ChildItem IIS:\Sites)) {
                Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath $site.PSPath -value False
                Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $site.name -filter "system.webServer/serverRuntime" -name "authenticatedUserOverride" -value "UseAuthenticatedUser"
                Set-WebConfigurationProperty -pspath $site.PSPath -filter "system.webServer/serverRuntime" -name "authenticatedUserOverride" -value "UseAuthenticatedUser" -ErrorAction SilentlyContinue
            }
        }
        net stop spooler
        sc.exe config spooler start=disabled

        ######### Misc #########
        # set font reg keys
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "segoeui.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "seguibl.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "seguibli.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "segoeuib.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "segoeuiz.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Emoji (TrueType)" /t REG_SZ /d "seguiemj.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "seguihis.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "segoeuii.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "segoeuil.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "seguili.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "seguisb.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "seguisbi.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "seguisli.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "seguisl.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "seguisym.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Variable (TrueType)" /t REG_SZ /d "segoeui.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe MDL2 Assets (TrueType)" /t REG_SZ /d "segmdl2.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print (TrueType)" /t REG_SZ /d "segoepr.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print Bold (TrueType)" /t REG_SZ /d "segoeprb.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script (TrueType)" /t REG_SZ /d "segoesc.ttf" /f
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script Bold (TrueType)" /t REG_SZ /d "segoescb.ttf" /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /f
        reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Auto Activation Mode" /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "InstallAsLink" /t REG_DWORD /d 0 /f
        reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Inactive Fonts" /f
        reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Active Languages" /f
        reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management\Auto Activation Languages" /f
        # set keyboard language to english
        Remove-ItemProperty -Path 'HKCU:\Keyboard Layout\Preload' -Name * -Force
        reg add "HKCU\Keyboard Layout\Preload" /v 1 /t REG_SZ /d "00000409" /f
        # set default theme
        Start-Process -Filepath "C:\Windows\Resources\Themes\aero.theme"
        timeout /t 3
        taskkill /im "systemsettings.exe" /f
        # set UI lang to english
        reg add "HKCU\Control Panel\Desktop" /v PreferredUILanguages /t REG_SZ /d en-US /f
        reg add "HKLM\Software\Policies\Microsoft\MUI\Settings" /v PreferredUILanguages /t REG_SZ /d en-US /f

        # CVE-2021-34527 (PrintNightmare)
        reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f
        # Network security: LDAP client signing requirements
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f
        reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
        # Disable BITS transfers
        reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f
        reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f
        # UAC
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
        # Anonymous Enumeration
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
        # Disable loading of test signed kernel-drivers
        Bcdedit.exe -set TESTSIGNING OFF
        Bcdedit.exe -set loadoptions ENABLE_INTEGRITY_CHECKS
        # Disable 8.3 file names
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f
        # Disable anonymous enumeration of shares and pipes
        Write-Host 1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
        Write-Host 2
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
        Write-Host 3
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
        Write-Host 4
        ######### Logging#########
        # Powershell command transcription
        reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f
        # Powershell script block logging
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
        ######### Constrained Language Mode #########
        [System.Environment]::SetEnvironmentVariable('__PSLockDownPolicy','4','Machine')

        ######### Sysmon Setup #########
        (new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon.exe',"$Home\Downloads\Sysmon.exe")
        (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',"$Home\Downloads\sysmonconfig-export.xml")
        .\sysmon.exe -accepteula -i sysmonconfig-export.xml
        $Error | Out-File $HOME\Documents\isb.txt -Append -Encoding utf8
    }
    else {
        # Write 2008 earlier os configs here
    }
}

Invoke-SecureBaseline
