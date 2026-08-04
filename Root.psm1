################################
# Import functions and classes #
################################

$ClassesFiles = Get-ChildItem -Path "$PSScriptRoot\classes" -Filter "*.ps1"
foreach ($file in $ClassesFiles) {
    . $file.FullName
}

$FunctionFiles = Get-ChildItem -Path "$PSScriptRoot\functions" -Filter "*.ps1"
foreach ($file in $FunctionFiles) {
    . $file.FullName
}
