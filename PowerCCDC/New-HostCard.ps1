function New-HostCard {
    param (
        [Parameter(Mandatory)]
        [String] $Board,
        [Parameter(Mandatory)]
        [String] $User,
        [Parameter(Mandatory)]
        [String] $System
    )
        if($null -eq (Get-TrelloBoard -Name $Board)) {
            Write-Host "A board with the name $BoardName does not exist, Invoke-CreateBoard to create a new board" 
        }
        else {
            $password = Read-Host "Enter a new password"
            $CardTitle = "Hostname (IP) [User]"
            $CardTitle = $CardTitle -Replace "Hostname", $(hostname)
            $CardTitle = $CardTitle -Replace "User", $User
            $description = "
# System Information

## Operating System:
PlaceHolder

## Admin User
username: $(whoami)
password: $password

## Other Details:
    Here"
            if ($System -eq 'Linux'){
                $IP = hostname -I
                $OperatingSystem = cat /etc/os-release  | grep PRETTY_NAME | sed 's/PRETTY_NAME=//' | sed 's/\"//g'
                $description = $description -Replace "PlaceHolder", $OperatingSystem
                $CardTitle = $CardTitle -Replace "IP", $IP
                $BoxCard = New-TrelloCard -ListID (Get-TrelloList -BoardId (Get-TrelloBoard -Name $Board | Select-Object -ExpandProperty id) | Select-Object name,id | Where-Object name -eq Linux | Select-Object -expand id) -Name $CardTitle -Description $description
                
                # Add comment with output of inventory script

            }
            elseif ($System -eq 'Windows') {
                $IP = Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Select-Object IPAddress | Where-Object IPAddress -NotLike '127.0.0.1' | Select-Object -ExpandProperty IPAddress
                $OperatingSystem = (Get-WmiObject -class Win32_OperatingSystem).Caption
                $description = $description -Replace "PlaceHolder", $OperatingSystem
                $CardTitle = $CardTitle -Replace "IP", $IP
                $BoxCard = New-TrelloCard -ListID (Get-TrelloList -BoardId (Get-TrelloBoard -Name $Board | Select-Object -ExpandProperty id) | Select-Object name,id | Where-Object name -eq Windows | Select-Object -expand id) -Name $CardTitle -Description $description
                
                # Manage Inventory However Windows team wants to
            }
            else {
                Write-Error 'OS needs to be either Windows or Linux'
            }
            New-TrelloCardChecklist -Card $BoxCard -Name Baselining -Item @('Inventory', 'Change Default Passwords', 'Configure Log Forwarding')
            New-TrelloCardChecklist -Card $BoxCard -name 'Password' -Item $password
    }
}