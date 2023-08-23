<# 
Example of importing the .JSON file from Get-WinHostInfo-PsExec.ps1
and querying for all hostnames with Intel NICs installed 
#>

# clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# set output location for json file
$jsonPath = Join-Path $scriptPath "WindowsHostsInfo.json"

# value for query
$queryValue = "*intel*"

# get content from .json file
$WindowsHosts = Get-Content -Path $jsonPath | ConvertFrom-Json

# get all devices w/ network interface description matching $queryValue
ForEach ($computer in $WindowsHosts.PSObject.Properties.Name) {
    $positive = $null # initialize variable
    ForEach ($network in $WindowsHosts.$computer.Network) {
        If ($network.InterfaceDescription -like "$queryValue"){
            $positive = $true
        }
    }
    If ($positive) {
        Write-Output $computer
    }
}
