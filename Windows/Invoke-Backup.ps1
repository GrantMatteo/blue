$ErrorActionPreference = "SilentlyContinue" # COMMENT IF U WANT TO SEE ERRORS
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
$Denied = @()
$Sessions = @()
$Ans = ""
mkdir $env:ProgramFiles\blue\windows\logs
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
    $Ans = Read-Host -Prompt "[WARNING] SOME COMPUTERS UNAVAILABLE, are you sure you want to continue? [y/n]"
    while ($Ans -ne "y" -and $Ans -ne "n") {
        $Ans = Read-Host -Prompt "[WARNING] SOME COMPUTERS UNAVAILABLE, are you sure you want to continue? [y/n]"
    }
} 
else {
    Write-Host "[INFO] Locked and loaded, fire away" -ForegroundColor Green
}
if ($Ans -eq "n") {
    Write-Host "[INFO] Exiting..." -ForegroundColor Yellow
    exit
}
if ($Ans -eq "y" -or $Denied.Count -eq 0) {
    foreach ($Session in $Sessions) {
        $Inventory = Invoke-Command -FilePath $env:ProgramFiles\blue\windows\TrelloAutomation\TrelloAutomation.ps1 -Session $Session -AsJob
        Write-Host "[INFO] Script invoked on $($Session.ComputerName)" -ForegroundColor Green
        Wait-Job $Inventory
        $r = Receive-Job $Inventory
        $r > $env:ProgramFiles\blue\windows\logs\$($Session.ComputerName).inventory
        Write-Host "[INFO] Inventory done for $($Session.ComputerName)" -ForegroundColor Green
    

        $Hardening = Invoke-Command -FilePath $env:ProgramFiles\blue\windows\Invoke-SecureBaseline.ps1 -Session $Session -AsJob
        Write-Host "[INFO] Script invoked on $($Session.ComputerName)" -ForegroundColor Green
        Wait-Job $Hardening
        $r = Receive-Job $Hardening
        $r > $env:ProgramFiles\blue\windows\logs\$($Session.ComputerName).baseline
        Write-Host "[INFO] hardening done for $($Session.ComputerName)" -ForegroundColor Green
    } 
}