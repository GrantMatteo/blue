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
OS_PLACEHOLDERh

## Admin User
username: $(whoami)
password: $password

## Other Details:
    DNS Servers: DNS_PLACEHOLDER"
            if ($System -eq 'Linux'){
                $IP = hostname -I
                $DNS = cat /etc/resolv.conf | grep nameserver | awk '{print $2}'
                $OperatingSystem = cat /etc/os-release  | grep PRETTY_NAME | sed 's/PRETTY_NAME=//' | sed 's/\"//g'
                $description = $description -Replace "OS_PLACEHOLDER", $OperatingSystem
                $description = $description -Replace "DNS_PLACEHOLDER", $DNS
                $CardTitle = $CardTitle -Replace "IP", $IP
                $BoxCard = New-TrelloCard -ListID (Get-TrelloList -BoardId (Get-TrelloBoard -Name $Board | Select-Object -ExpandProperty id) | Select-Object name,id | Where-Object name -eq Linux | Select-Object -expand id) -Name $CardTitle -Description $description
                $userchecklist = New-TrelloCardChecklist -Card $BoxCard -Name users
                $servicechecklist = New-TrelloCardChecklist -Card $BoxCard -Name services
                $inboundchecklist = New-TrelloCardChecklist -Card $BoxCard -Name inbound
                $outboundchecklist = New-TrelloCardChecklist -Card $BoxCard -Name outbound
                $users = cat /etc/passwd | grep -vE 'false|nologin|sync' | awk -F ":" '{print $1}'
                $outbound = netstat -tupwn | grep -E 'tcp|udp' | awk '{print $5,$7}'
                $inbound = netstat -tulpen | grep -E 'tcp|udp' | awk '{print $4,$9}'
                foreach ($user in $users){New-TrelloCardChecklistItem -Checklist $userchecklist -Name $user}
                if ($null -eq (which systemctl)){$services = systemctl --type=service  | grep active | awk '{print $1}'}
                else{$services = service --status-all | grep -i '+' | awk -F "]  " '{print $2}'}
                foreach ($service in $services){mNew-TrelloCardChecklistItem -Checklist $servicechecklist -Name $service}
                foreach ($connection in $outbound){New-TrelloCardChecklistItem -Checklist $outboundchecklist -Name $connection}
                foreach ($connection in $inbound){New-TrelloCardChecklistItem -Checklist $inboundchecklist -Name $connection}
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