################################
# Import functions and classes #
################################

[hashtable]$Params = @{
    Filter      = "*.ps1"
    File        = $true
    ErrorAction = "Stop"
}

# [System.IO.FileInfo[]]$ClassesFiles = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "classes") @Params
# foreach ($file in $ClassesFiles) {
#     . $file.FullName
# }

[System.IO.FileInfo[]]$FunctionFiles = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "functions") @Params
foreach ($file in $FunctionFiles) {
    . $file.FullName
}
