function Invoke-Baseline {
    param (
        [Parameter(Mandatory)]
        [String] $Board
    )
    if ($null -eq (Get-TrelloCard -board (Get-TrelloBoard -name $board) | Where-Object {$_.name -like "*$(hostname)*"})){
        Write-Host "A card containing $(hostname) does not exist, please use Invoke-Inventory to create a new card"
    } else{
        if ($null -eq (Get-TrelloCard -board (Get-TrelloBoard -name $board) | Where-Object {$_.name -like "*$(hostname)*"}| Get-TrelloCardChecklist -Name Baselining | Get-TrelloCardChecklistItem)){
            Invoke-PasswordChange -Card (Get-TrelloCard -board (Get-TrelloBoard -name CCDC) | Where-Object {$_.name -like "*$(hostname)*"})
        }
    }
}

function Invoke-PasswordChange {
    param (
       [Parameter(Mandatory)]
       [String] $Card
    )
    $password = Get-TrelloCard -board (Get-TrelloBoard -name $board) | Get-TrelloCardChecklist -Name password | Get-TrelloCardChecklistItem | Select-Object -expand name
}