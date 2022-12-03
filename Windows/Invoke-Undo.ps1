function Test-WinRM {
    $Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
    $Denied = @()
    foreach ($Computer in $Computers) {
        try {
            $session = New-PSSession -ComputerName $env:COMPUTERNAME
            $session | Remove-PSSession
        }
        catch {
            $Denied += $Computer
            Write-Host "[ERROR] Failed: $Computer" -ForegroundColor Red
        }
    }
}

function Get-Assets {
    # Get sysinternals tools
}