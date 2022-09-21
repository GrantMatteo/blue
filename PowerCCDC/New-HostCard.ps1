function New-HostCard {
    param (
        [Parameter(Mandatory)]
        [String] $BoardName,
        [Parameter(Mandatory)]
        [String] $User,
        [Parameter(Mandatory)]
        [String] $OS
    )
        if($null -eq (Get-TrelloBoard -Name $BoardName)) {
            Write-Host "A board with the name $BoardName does not exist, Invoke-CreateBoard to create a new board" 
        }
        else {
            $hostname = hostname
            if ($OS -eq 'Linux'){
                $ip = 'something'
            }
            elseif ($OS -eq 'Windows') {
                $ip = 'something'
            }
            else {
                Write-Error 'OS needs to be either Windows or Linux'
            }
            $password = Read-Host "Enter a new password"
            $CardTitle = -join($hostname," (",$ip,") ",'[', $User,"] ") 
            $description = "# System Information:
 ## Operating System:

 ## Admin User
username: $(whoami)
password: $password

## Other Details:
    Here"
            $BoxCard = New-TrelloCard -ListID (Get-TrelloList -BoardId (Get-TrelloBoard -Name $BoardName | Select-Object -ExpandProperty id) | Select-Object name,id | Where-Object name -eq $OS | Select-Object -expand id) -Name $CardTitle -Description $description
            New-TrelloCardChecklist -Card $BoxCard -Name Baselining -Item @('Inventory', 'Change Default Passwords', 'Configure Log Forwarding')
            New-TrelloCardChecklist -Card $BoxCard -name 'Password' -Item $password
    }
}