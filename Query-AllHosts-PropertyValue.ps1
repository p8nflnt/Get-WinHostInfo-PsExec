<# 
Example of importing the .JSON file generated by Get-WinHostInfo-PsExec.ps1
and querying for all hostnames with a property value.
This example will retrieve all hostnames w/ Intel NICs installed. 
#>

# clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# set .JSON file location
$jsonPath = Join-Path $scriptPath "WindowsHostsInfo.json"

# set output location for .csv
$outputPath = Join-Path $scriptPath "QueryOutput.csv"

# select query type: 
# System, Network, Win32Apps, AppxApps, Drivers
$queryType =     "Network"
# select query property:
$queryProperty = "InterfaceDescription"
# specify value for query:
$queryValue =    "*intel*"

# get content from .json file
$WindowsHosts = Get-Content -Path $jsonPath | ConvertFrom-Json

# initialize output array
$output = @()

# get all devices w/ $queryType, $queryProperty matching $queryValue
ForEach ($computer in $WindowsHosts.PSObject.Properties.Name) {
    $positive = $null # initialize variable
    ForEach ($item in $WindowsHosts.$computer.$queryType) {
        If ($item.$queryProperty -like "$queryValue"){
            $positive = $true
        }
    }
    If ($positive) {
        Write-Output $computer
        # add computer to output array
        $output += $computer
    }
}

# export to .csv
$output `
| Sort-Object -Unique `
| Out-File $outputPath -Force
