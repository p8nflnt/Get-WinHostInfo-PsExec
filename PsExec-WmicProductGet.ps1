<#
this is a standalone script to return results of 'wmic product get' via PsExec on a target host
and convert results back into usable PoSh objects.
Intended to be added to Get-WinHostInfo-PsExec script to expand capability
'wmic product get' returns additional app info like installation directory & date
#>

# clear variables
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# target hostname
$computerName = "<INSERT HOSTNAME>"

# function for timestamp
$timestamp = Get-Date -UFormat "%Y-%m-%d@%H%M"

# build output file path
$outputPath = "$scriptPath" + "\" + "$computerName" + "_" + "$timestamp" + ".json"

# get apps from target host w/ PsExec
$output = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "wmic product get /format:list" 2> $null

# if output is not null...
If ($output) {

    # extract text lines
    $textExtract = ($output -split "`r?`n").Trim() | Where-Object { $_ }

    # reassemble text lines
    $textExtract = $textExtract -join "`r`n"

    # identify app blocks & drop empty blocks
    $appBlocks = ($textExtract -split "(?msi)(?=^AssignmentType=\d+)") | Where-Object { $_ }

    # initialize an empty array to store application objects
    $appArray = @()

    # process each application block
    foreach ($block in $appBlocks) {
        # split the block into lines
        $lines = $block -split "`n"

        # initialize an empty hashtable to store application properties
        $appProps = @{}

        # loop through each line and create a hashtable of properties and values
        foreach ($line in $lines) {
            $key, $value = $line -split '=', 2
            if ($value) {
                $appProps[$key] = $value
            }
        }

        # create a custom object from the hashtable
        $appObject = [PSCustomObject]$appProps

        # add the application object to the array
        $appArray += $appObject
    }

    # export app array to json & correct formatting
    ($appArray | ConvertTo-Json -depth 100).Replace('\r"','"') | Out-File "$outputPath" -Force
} Else {
    Write-Host -ForegroundColor Red "No response from host."
}
