function Invoke-Baseline {
    param (
        [Parameter(Mandatory)]
        [String] $Board
    )
    if ($null -eq (Get-TrelloCard -board (Get-TrelloBoard -name $board) | Where-Object {$_.name -like "*$(hostname)*"})){
        Write-Host "A card containing $(hostname) does not exist, please use Invoke-Inventory to create a new card"
    } else{
        
    }
}