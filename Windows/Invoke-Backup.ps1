$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
$Denied = @()
$Sessions = @()
foreach ($Computer in $Computers) {
    try {
        $TestSession = New-PSSession -ComputerName $Computer
        $Sessions += $TestSession
    }
    catch {
        $Denied += $Computer
        Write-Host "[ERROR] Failed: $Computer" -ForegroundColor Red
    }
}

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