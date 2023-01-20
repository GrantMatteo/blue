$ErrorActionPreference = "SilentlyContinue" # COMMENT IF U WANT TO SEE ERRORS
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
$Denied = @()
$Sessions = @()
foreach ($Computer in $Computers) {
    $TestSession = New-PSSession -ComputerName $Computer
    if ($TestSession) {
        $Sessions += $TestSession
        Write-Host "[INFO] Preparing to WinRM to: $Computer" -ForegroundColor Green
    }
    else {
        $Denied += $Computer
        Write-Host "[ERROR] Failed: $Computer" -ForegroundColor Red
    }
}

if ($Denied.Count -gt 0) {
    $Ans = Read-Host -Prompt "Not All computers have WinRM enabled, are you sure you want to continue? [y/n]"
    while ($Ans -ne "y" -and $Ans -ne "n") {
        $Ans = Read-Host -Prompt "Not All computers have WinRM enabled, are you sure you want to continue? [y/n]"
    }
}
if ($Ans -eq "n") {
    Write-Host "[INFO] Exiting..." -ForegroundColor Yellow
    exit
}
if ($Ans -eq "y" -or $Denied.Count -eq 0) {
    foreach ($Session in $Sessions) {
        Read-Host -Prompt "Continue with invetory? Press Enter to continue."
        $Inventory = Invoke-Command -FilePath $env:ProgramFiles\blue\windows\TrelloAutomation\TrelloAutomation.ps1 -Session $Session -AsJob
        Wait-Job $Inventory
        $r = Receive-Job $Inventory
        $r | ForEach-Object {$_ > $env:ProgramFiles\blue\windows\logs\$($_.PSComputerName).trlout}
    
        Read-Host -Prompt "Continue with Hardening? Press Enter to continue."
        $Hardening = Invoke-Command -FilePath $env:ProgramFiles\blue\windows\Invoke-SecureBaseline.ps1 -Session $Session -AsJob
        Wait-Job $Hardening
        $r = Receive-Job $Hardening
        $r | ForEach-Object {$_ > $env:ProgramFiles\blue\windows\logs\$($_.PSComputerName).secbout}
    } 
}