# Get Module out of current path or place in a path or append to $env:PSModulePath
Import-Module .\Get-SystemInformation
$data = Get-SystemInformation

Write-Host $data