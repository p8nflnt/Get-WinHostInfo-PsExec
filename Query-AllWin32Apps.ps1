# clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# set .JSON file location
$jsonPath = Join-Path $scriptPath "WindowsHostsInfo.json"

# set output location for .csv
$outputPath = Join-Path $scriptPath "Win32AppsOutput.csv"

# select query type:
$queryType =     "Win32Apps"

# get content from .json file
$WindowsHosts = Get-Content -Path $jsonPath | ConvertFrom-Json

# initialize output array
$output = @()

# get all items of matching queryType from WindowsHosts
ForEach ($computer in $WindowsHosts.PSObject.Properties.Name) {
    ForEach ($item in $WindowsHosts.$computer.$queryType) {
        $output += $item
    }
}

# deduplicate and export to .csv
$output `
| Sort-Object -Unique -Property { $_.Caption + $_.Vendor + $_.Name + $_.Version + $_.IdentifyingNumber } `
| Out-File $outputPath -Force
