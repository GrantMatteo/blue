$ErrorActionPreference = "Continue" # COMMENT IF U WANT TO SEE ERRORS
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty Name
$Denied = @()
$Sessions = @()
$admin = Read-Host -Prompt "[PROMPT] Admin name: "
mkdir $env:ProgramFiles\blue-main\windows\logs
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
        $Inventory = Invoke-Command -FilePath $env:ProgramFiles\blue-main\windows\TrelloAutomation\TrelloAutomation.ps1 -Session $Session -AsJob
        Write-Host "[INFO] Inventory Script invoked on $($Session.ComputerName)" -ForegroundColor Green
        Wait-Job $Inventory
        $r = Receive-Job $Inventory
        $r > $env:ProgramFiles\blue-main\windows\logs\$($Session.ComputerName).inventory
        Write-Host "[INFO] Inventory done for $($Session.ComputerName)" -ForegroundColor Green
    }

    $Ans2 = Read-Host -Prompt "[INFO] Start hardening? [y/n]"
    while ($Ans2 -ne "y" -and $Ans2 -ne "n") {
        $Ans2 = Read-Host -Prompt "[INFO] Start hardening? [y/n]"
    }
    if ($Ans2 -eq "y") {
        foreach ($Session in $Sessions) {
            $Hardening = Invoke-Command -FilePath $env:ProgramFiles\blue-main\windows\Invoke-SecureBaseline.ps1 -ArgumentList "$admin" -Session $Session -AsJob
            Write-Host "[INFO] Hardening Script invoked on $($Session.ComputerName)" -ForegroundColor Green
            Wait-Job $Hardening
            $r = Receive-Job $Hardening
            $r > $env:ProgramFiles\blue-main\windows\logs\$($Session.ComputerName).baseline
            Write-Host "[INFO] hardening done for $($Session.ComputerName)" -ForegroundColor Green
        }  
    }
    else {
        Write-Host "[INFO] Exiting..." -ForegroundColor Yellow
        exit
    }
}
Get-PSSession | Remove-PSSession