# clear variables
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# specify appx name
$appxName = "<INSERT APPX PACKAGE NAME>"

# target hostname
$computerName = "<INSERT HOSTNAME>"

psexec.exe -s -nobanner -h \\$computerName Powershell.exe -ExecutionPolicy Bypass -Command "Get-AppxPackage -AllUsers | Where-Object -Property Name -Like '$appxName' | Remove-AppxPackage -AllUsers" 2> $null
