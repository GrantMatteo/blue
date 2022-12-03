function Invoke-SecureBaseline {

    Param(
        [switch]$Pre2008OnPrem,
        [switch]$2008r2OnPrem,
        [string]$shareip,
        [string]$sharename
        )
    
    Set-ExecutionPolicy Unrestricted -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    $Error.Clear()
    $ErrorActionPreference = "SilentlyContinue"
    $DC = $false
    $OS = (Get-WMIObject win32_operatingsystem).caption
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
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    # TODO: see if this automatically removes shares
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
    net share C$ /delete | Out-Null
    net share ADMIN$ /delete | Out-Null
    Write-Host "$env:ComputerName: SMB shares deleted and settings applied" -ForegroundColor Green
    ######### Reset Policies #########
    Copy-Item C:\Windows\System32\GroupPolicy* C:\gp -Recurse | Out-Null
    Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force | Out-Null
    gpupdate /force
    Write-Host "$env:ComputerName: Group Policy reset" -ForegroundColor Green

    ######### User Auditing #########
    Add-Type -AssemblyName System.Web
    $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
    while ($p -match '[,;:|iIlLoO0]') {
        $p = [System.Web.Security.Membership]::GeneratePassword(14,4)
    }

    if ($DC) {
        Get-WmiObject -class win32_useraccount | Where-object {$_.name -ne "krbtgt" -and $_.name -ne "deaters"} | ForEach-Object {net user $_.name $p > $null}
        
        $ADUsers = Get-ADUser -Filter *
        $ADUsers | Set-ADUser -AllowReversiblePasswordEncryption 0 -PasswordNotRequired 0
        Get-ADGroupMember -Identity "Administrators" | Where-Object {$_.name -ne "Domain Admins" -and $_.name -ne "Enterprise Admins" -and $_.SamAccountName -ne "deaters"} | ForEach-Object {Remove-ADGroupMember -Identity "Administrators" -Members $_.SamAccountName -confirm:$false}
        Get-ADGroupMember -Identity "Domain Admins" | Where-Object {$_.SamAccountName -ne "deaters"} | ForEach-Object {Remove-ADGroupMember -Identity "Domain Admins" -Members $_.SamAccountName -confirm:$false}
        Get-ADGroupMember -Identity "Enterprise Admins" | Where-Object {$_.SamAccountName -ne "deaters"} | ForEach-Object {Remove-ADGroupMember -Identity "Enterprise Admins" -Members $_.SamAccountName -confirm:$false}
        $p2 = "N/A"
    }
    else {
        $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
        while ($p2 -match '[,;:|iIlLoO0]') {
            $p2 = [System.Web.Security.Membership]::GeneratePassword(14,4)
        }
        Get-WmiObject -class win32_useraccount | Where-object {$_.name -ne "deaters"} | ForEach-Object {net user $_.name $p > $null}
        net user deaters $p2 /add | Out-Null
        # net localgroup Administrators | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -skip 4 | ForEach-Object {net localgroup Administrators $_ /delete > $null}
        net localgroup Administrators deaters /add | Out-Null
    }
    Write-Host "$env:ComputerName: User auditing complete" -ForegroundColor Green

    if ($OS -match  "ista|2008|2003|XP|xp|Xp|7") {
        Write-Host "$env:COMPUTERNAME: [INFO] deaters:$p2" -ForegroundColor Magenta -BackgroundColor Black
        Write-Host "$env:COMPUTERNAME: [INFO] All:$p" -ForegroundColor Magenta -BackgroundColor Black
    }

    Unblock-File "$env:ProgramFiles\TrelloAutomation\TrelloAutomation.ps1"
    $action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-WindowStyle Hidden -NoProfile -file `"C:\Program Files\TrelloAutomation\TrelloAutomation.ps1`" $p, $p2"
    $task = New-ScheduledTask -Action $action -Trigger $trigger
    Register-ScheduledTask -TaskName "Trello" -InputObject $task
    Start-ScheduledTask -TaskName "Trello"
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName "Trello" -Confirm:$false
    Write-Host "$env:ComputerName: Trello automation completed" -ForegroundColor Green

    ######### PTH Mitigation #########
    # Disable storage of the LM hash for passwords less than 15 characters
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
    # Network security: LAN Manager authentication level
    # Do not send LM or NTLM responses, only NTLMv2
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
    
    if (!$Pre2008OnPrem -and !$2008r2OnPrem) {
        # Deny all NTLM authentication in the domain
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RestrictNTLMInDomain /t REG_DWORD /d 7 /f | Out-Null
        # Deny all inbound and outbound NTLM + audit attempts
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d 2 /f | Out-Null
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d 2 /f | Out-Null
    }
    # Disable storage of plaintext creds in WDigest
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
    # Enable remote UAC for Local accounts
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f | Out-Null
    # Enable LSASS Protection
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
    # Enable LSASSS process auditing
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
    Write-Host "$env:ComputerName: PTH Mitigation complete" -ForegroundColor Green

    ######### Defender #########
    #TODO: Hardcode all defender defaults

    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
    try {
        # Block Office applications from injecting code into other processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block Office applications from creating executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block all Office applications from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block JavaScript or VBScript from launching downloaded executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block execution of potentially obfuscated scripts
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block executable content from email client and webmail
        Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block Win32 API calls from Office macro
        Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block process creations originating from PSExec and WMI commands
        Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block untrusted and unsigned processes that run from USB
        Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Use advanced protection against ransomware
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
        Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block Office communication application from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block Adobe Reader from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        # Block persistence through WMI event subscription
        Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
        Write-Host "$env:ComputerName: Defender Attack Surface Reduction rules enabled" -ForegroundColor Green
        ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
            Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null
        }
        ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
            Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null
        }
        ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
            Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null
        }
        ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
            Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null
        }
        ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null
        }
        Write-Host "$env:ComputerName: Defender exclusions removed" -ForegroundColor Green
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Host "$env:ComputerName: [INFO] Old defender version detected, skipping ASR rules" -ForegroundColor Yellow
    }
    catch {
        Write-Host "$env:ComputerName: [ERROR] man wtf goin on over here with defender ASR" -ForegroundColor Red
    }
    ######### Disable PHP Functions #########
    $php = Get-ChildItem C:\ php.exe -recurse -ErrorAction SilentlyContinue | ForEach-Object {& $_.FullName --ini | Out-String}
    $ConfigFiles = @()
    ForEach($OutputLine in $($php -split "`r`n")) {
        if ($OutputLine -match 'Loaded') {
            ForEach-Object {
                $ConfigFiles += ($OutputLine -split "\s{9}")[1]
            }
        }
    }
    $ConfigString = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
    file_uploads=off"
    Foreach ($ConfigFile in $ConfigFiles) {
        Add-Content $ConfigFile $ConfigString
    }
    Write-Host "$env:ComputerName: PHP functions disabled" -ForegroundColor Green
    ######### Local Policies #########
    Copy-Item "\\$shareip\$sharename\stigs.inf" -Destination "$Home\Downloads\stigs.inf"
    # (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/cpp-cyber/blue/main/Windows/stigs.inf',"$Home\Downloads\stigs.inf")
    Write-Output Y | Secedit /configure /db secedit.sdb /cfg "$Home\Downloads\stigs.inf" /overwrite
    Write-Host "$env:ComputerName: Local Policies configured" -ForegroundColor Green
    ######### Service Lockdown #########
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d 1 /f
    if ($DC) {
        Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
        # CVE-2020-1472 (Zerologon)
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force | Out-Null
        # CVE-2021-42278 & CVE-2021-42287 (noPac)
        Set-ADDomain -Identity $Domain -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
        # TODO: Domain Member: Digitally encrypt or sign secure channel data (always) - Enabled works 2008
        if ($2008r2OnPrem) {
            # Domain controller: LDAP server signing requirements
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
            # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before supposedly)
            # TODO: Test below for 2008r2 
            reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f | Out-Null
        }
        elseif ($Pre2008OnPrem) {
            # Domain controller: LDAP server signing requirements
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 1 /f | Out-Null
            # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before)
            reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f | Out-Null
        }
        else {
            # Domain controller: LDAP server signing requirements
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
            # Domain controller: LDAP server channel binding token requirements (1 for 2008 and before)
            reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f | Out-Null
        }
        
    }

    if ($IIS) {
        foreach ($app in (Get-ChildItem IIS:\AppPools)) {
            C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.applicationHost/applicationPools "/[name='$($app.name)'].processModel.identityType:`"ApplicationPoolIdentity`"" /commit:apphost
        }            
        foreach ($site in (Get-ChildItem IIS:\Sites)) {
            C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/directoryBrowse /enabled:"False"
            C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/serverRuntime /authenticatedUserOverride:"UseAuthenticatedUser"  /commit:apphost
        }
    }
    net stop spooler | Out-Null
    sc.exe config spooler start=disabled | Out-Null
    Write-Host "$env:ComputerName: Services locked down" -ForegroundColor Green
    ######### Misc #########
    # set font reg keys
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "seguibl.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "seguibli.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "segoeuib.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "segoeuiz.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Emoji (TrueType)" /t REG_SZ /d "seguiemj.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "seguihis.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "segoeuii.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "segoeuil.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "seguili.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "seguisb.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "seguisbi.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "seguisli.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "seguisl.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "seguisym.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Variable (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe MDL2 Assets (TrueType)" /t REG_SZ /d "segmdl2.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print (TrueType)" /t REG_SZ /d "segoepr.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print Bold (TrueType)" /t REG_SZ /d "segoeprb.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script (TrueType)" /t REG_SZ /d "segoesc.ttf" /f | Out-Null
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script Bold (TrueType)" /t REG_SZ /d "segoescb.ttf" /f | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Auto Activation Mode" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "InstallAsLink" /t REG_DWORD /d 0 /f | Out-Null
    reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Inactive Fonts" /f | Out-Null
    reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Active Languages" /f | Out-Null
    reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management\Auto Activation Languages" /f | Out-Null
    # set keyboard language to english
    Remove-ItemProperty -Path 'HKCU:\Keyboard Layout\Preload' -Name * -Force | Out-Null
    reg add "HKCU\Keyboard Layout\Preload" /v 1 /t REG_SZ /d "00000409" /f | Out-Null
    # set default theme
    Start-Process -Filepath "C:\Windows\Resources\Themes\aero.theme"
    # set UI lang to english
    reg add "HKCU\Control Panel\Desktop" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\MUI\Settings" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
    Write-Host "$env:ComputerName: Font, Themes, and Languages set to default" -ForegroundColor Green

    # CVE-2021-34527 (PrintNightmare)
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
    # Network security: LDAP client signing requirements
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f | Out-Null
    # Disable BITS transfers
    reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
    # UAC
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
    # Anonymous Enumeration
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f | Out-Null
    # Disable loading of test signed kernel-drivers
    Bcdedit.exe -set TESTSIGNING OFF | Out-Null
    Bcdedit.exe -set loadoptions ENABLE_INTEGRITY_CHECKS | Out-Null
    # Disable 8.3 file names
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f | Out-Null
    # Disable anonymous enumeration of shares and pipes
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /f | Out-Null
    Write-Host "$env:ComputerName: Misc hardening done" -ForegroundColor Green
    ######### Logging#########
    # Powershell command transcription
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f | Out-Null
    # Powershell script block logging
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
    Write-Host "$env:ComputerName: Powershell Logging enabled" -ForegroundColor Green
    ######### Constrained Language Mode #########
    #[System.Environment]::SetEnvironmentVariable('__PSLockDownPolicy','4','Machine')

    ######### Sysmon Setup #########
    Copy-Item "\\$shareip\$sharename\Sysmon.exe" -Destination "C:\Windows\System32\Sysmon.exe"
    Copy-Item "\\$shareip\$sharename\sysmonconfig-export.xml" -Destination "C:\Windows\System32\smce.xml"
    # (new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon.exe',"C:\Windows\System32\Sysmon.exe")
    # (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',"C:\Windows\System32\smce.xml")
    & "C:\Windows\System32\Sysmon.exe" -accepteula -i C:\Windows\System32\smce.xml
    Write-Host "$env:ComputerName: Sysmon installed and configured" -ForegroundColor Green
    $Error | Out-File $HOME\Desktop\isb.txt -Append -Encoding utf8
}

Invoke-SecureBaseline -shareip "IP" -sharename "sharename"