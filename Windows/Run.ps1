param(
    [Parameter(Mandatory=$true)]
    [String]$Script,

    [Parameter(Mandatory=$true)]
    [String]$Out
)



$ErrorActionPreference = "Continue"
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty Name
$Denied = @()
$Sessions = @()

if ($Script -eq "$env:ProgramFiles\blue-main\windows\Users.ps1") {
    $admin = Read-Host -Prompt "[PROMPT] Admin name: "
}

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
        $ScriptJob = Invoke-Command -FilePath $Script -Session $Session -AsJob
        Write-Host "[INFO] Inventory Script invoked on $($Session.ComputerName)" -ForegroundColor Green
        Wait-Job $ScriptJob
        $r = Receive-Job $ScriptJob
        #TODO test
        $r > $Out\$($Session.ComputerName).inventory
        Write-Host "[INFO] Script done for $($Session.ComputerName)" -ForegroundColor Green
    }
}
Get-PSSession | Remove-PSSession