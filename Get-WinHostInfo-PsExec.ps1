<#
.SYNOPSIS
    Retrieve System, Network, Application, Driver, and Primary user information 
    from all hosts in your domain - even if they may have WinRM, IIS, and PS-Remoting
    disabled by using PsExec of the Sysinternals suite.

.NOTES
    Name: Get-WinHostInfo-PsExec.ps1
    Author: Payton Flint
    Version: 1.4
    DateCreated: 2023-Aug

.LINK
    https://github.com/p8nflnt/Get-WinHostInfo-PsExec/blob/main/Get-WinHostInfo-PsExec.ps1
    https://paytonflint.com/powershell-get-windows-host-info-with-psexec/
#>

# clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# filename for Get-UserDeviceAffinity script
$GetUserDeviceAffinity = "Get-UserDeviceAffinity.ps1"
# build UNC path
$GetUserDeviceAffinity = '\\' + $env:COMPUTERNAME + '\' + $ScriptPath.Replace(':', '$') + '\' + $GetUserDeviceAffinity

# set output location for json file
$outputPath = Join-Path $scriptPath "WindowsHostsInfo.json"

# specify timeout & throttle limit
# these affect performance
$Timeout       = 300 # timeout in seconds
$ThrottleLimit = 8   # batch size, running ThreadJobs will be 2x this number because of corresponding timer jobs

# get all enabled computers from AD that can be pinged
$computerList = @()
$computerList += Get-ADComputer -Filter {Enabled -eq $true} -Properties Name | 
   Where-Object {Test-Connection -ComputerName $_.Name -Count 1 -Quiet} | 
    Select-Object -Property Name | 
    Sort-Object -Property Name

# chunk the computer names into groups based on the throttle limit
$chunks = @()
for ($i = 0; $i -lt $computerList.Count; $i += $ThrottleLimit) {
    $chunk = $computerList[$i..($i + $ThrottleLimit - 1)]
    $chunks += ,@($chunk)
}

# check for ThreadJob module, if not present, install
Function Install-Module {
    param (
        $name
    )
    $presence = Get-InstalledModule -Name $name -ErrorAction SilentlyContinue
        If (-not $presence) {
        Find-Module $name -ErrorAction SilentlyContinue | Install-Module -Force
    }
} # end function Install-Module
Install-Module -name ThreadJob

# check for PsExec, if not present, install
Function Install-PsExec {
    param (
        [bool]$AcceptEULA
    )
    Function RegEdit {
        param(
        $regPath,
        $regName,
        $regValue,
        [bool]$silent
        )
        $regFull = Join-Path $regPath $regName
            Try {
                    $CurrentKeyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
                    If (Test-Path $regPath) {
                        If ($CurrentKeyValue -eq $regValue) {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Green 'Registry key' $regFull 'value is set to the desired value of' $regValue'.'
                            }
                            $script:regTest = $True  
                        } Else {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Red 'Registry key' $regFull 'value is not' $regValue'.'
                                Write-Host -ForegroundColor Cyan 'Setting registry key' $regFull 'value to' $regValue'.'
                            }
                            New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWORD -Force | Out-Null
                            $CurrentKeyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
                            If ($CurrentKeyValue -eq $regValue) {
                                If (!($silent)) {
                                    Write-Host -ForegroundColor Green 'Registry key' $regFull 'value is set to the desired value of' $regValue'.'
                                }
                                $script:regTest = $True  
                            } Else {
                                If (!($silent)) {
                                    Write-Host -ForegroundColor Red 'Registry key' $regFull 'value could not be set to' $regValue '.'
                                }
                            }
                        }
                    } Else {
                        If (!($silent)) {
                            Write-Host -ForegroundColor Red 'Registry key' $regFull 'path does not exist.'
                            Write-Host -ForegroundColor Cyan 'Creating registry key' $regFull'.'
                        }
                        New-Item -Path $regPath -Force | Out-Null
                        If (!($silent)) {
                            Write-Host -ForegroundColor Cyan 'Setting registry key' $regFull 'value to' $regValue'.'
                        }
                        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWORD -Force | Out-Null
                        $CurrentKeyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
                        If ($CurrentKeyValue -eq $regValue) {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Green 'Registry key' $regFull 'value is set to the desired value of' $regValue'.'
                            }
                            $script:regTest = $True  
                        } Else {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Red 'Registry key' $regFull 'value could not be set to' $regValue '.'
                            }
                        }
                    }
            } Catch {
                If (!($silent)) {
                    Write-Host -ForegroundColor Red 'Registry key' $regFull 'value could not be set to' $regValue '.'
                }
            }
    } # End RegEdit Function

    $PsExec = Get-Command psexec -ErrorAction SilentlyContinue
    If($PsExec){
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            RegEdit -regPath "HKCU:\SOFTWARE\Sysinternals\PsExec" -regName "EulaAccepted" -regValue "1" -silent $true
        }
    } Else {
        # courtesy of Adam Bertram @ https://adamtheautomator.com/psexec/
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
        Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
        Move-Item -Path "$env:TEMP\pstools\psexec.exe" .
        Remove-Item -Path "$env:TEMP\pstools" -Recurse
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            RegEdit -regPath "HKCU:\SOFTWARE\Sysinternals\PsExec" -regName "EulaAccepted" -regValue "1" -silent $true
        }
    }
} # end function Install-PsExec
Install-PsExec -AcceptEULA $True

# start Get-ComputerInfo function
Function Get-ComputerInfo {
    param (
        $computerList,
        [int]$Timeout,
        [int]$ThrottleLimit,
        $outputPath,
        [bool]$appx,           # only specify if desired (large dataset)
        [bool]$drivers,        # only specify if desired (large dataset) 
        $GetUserDeviceAffinity # file path for Get-UserDeviceAffinity.ps1 (only specify if desired)
    )
    # start GetCompInfo scriptblock
    $GetCompInfo = {
        param (
            $computerName,
            $GetUserDeviceAffinity,
            $WindowsHosts,
            $outputPath,
            [bool]$appx,       # only specify if desired (large dataset)
            [bool]$drivers     # only specify if desired (large dataset) 
        )

        # start function ConvertTo-Objects
        Function ConvertTo-Objects {
            param (
                $inputString
            )
            # split the input string into lines
            $lines = $inputString -split "`r?`n"

            # initialize an empty array to hold objects
            $objects = @()
            # initialize an empty hashtable to hold property values for the current application
            $properties = @{}

            # iterate through each line and extract property and value using regex
            foreach ($line in $lines) {
                # check if the line is empty or contains only whitespace
                if ([string]::IsNullOrWhiteSpace($line)) {
                    # if an empty line is encountered, create an object and add it to the array
                    if ($properties.Count -gt 0) {
                        $object = [PSCustomObject]$properties
                        $objects += $object
                        $properties = @{}  # Reset properties for the next application
                    }
                } elseif ($line -match '^(.*?):\s*(.*)$') {
                    # use regex to split the line into property and value
                    $property = $matches[1].Trim()
                    $value = $matches[2].Trim()

                    if ($property -ne '') {
                        $properties[$property] = $value
                    }
                }
            }
            # if there are properties left, create the last object and add it to the array
            if ($properties.Count -gt 0) {
                $object = [PSCustomObject]$properties
                $objects += $object
            }
            # return the resulting objects
            Write-Output $objects
        } # end function ConvertTo-Objects
            
        # initial run w/ PsExec
        $compInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-ComputerInfo" 2> $null
        $compInfo = ConvertTo-Objects -inputString $compInfo

        # use Get-ComputerInfo as litmus test for whether device is responsive & Windows OS
        # further actions are contingent on Get-ComputerInfo results (increases performance)
        if ($compInfo) {
            # get network info & convert to objects
            $netInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-NetIPConfiguration" 2> $null
            $netInfo = ConvertTo-Objects -inputString $netInfo
            # get  win32 application info & convert to objects
            $appInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-WmiObject -Class Win32_Product" 2> $null
            $appInfo = ConvertTo-Objects -inputString $appInfo
            # create output object w/ above objects
            $output = [PSCustomObject]@{
                    System    = $compInfo
                    Network   = $netInfo
                    Win32Apps = $appInfo
            }
            # if appx is specified, get appx package info, convert to objects, and add to output
            if ($appx) {
                $appxInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-AppxPackage -AllUsers | Select-Object Name, Version, Publisher | Format-List" 2> $null
                $appxInfo = ConvertTo-Objects -inputString $appxInfo
                $output | Add-Member -MemberType NoteProperty -Name "AppxApps" -Value $appxInfo
            }
            # if drivers is specified, get driver info, convert to objects, and add to output
            if ($drivers) {
                $driverInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-WmiObject -Class Win32_PnPSignedDriver" 2> $null
                $driverInfo = ConvertTo-Objects -inputString $driverInfo
                $output | Add-Member -MemberType NoteProperty -Name "Drivers" -Value $driverInfo
            }
            # if GetUserDeviceAffinity param is specified, add primary user property
            if ($GetUserDeviceAffinity) {
                $primaryUser = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -NoInteractive -ExecutionPolicy Bypass -File "$GetUserDeviceAffinity" 2> $null
                $primaryUser = ConvertTo-Objects -inputString $primaryUser
                $output | Add-Member -MemberType NoteProperty -Name "PrimaryUser" -Value $primaryUser
            }
            # Add output to WindowsHosts & export to .json output file
            $windowsHosts | Add-Member -MemberType NoteProperty -Name $computerName -Value $output
            $windowsHosts | ConvertTo-Json -depth 100 | Out-File "$outputPath" -Force
            Write-Output "$computerName - information retrieved successfully."
        }
    } # end GetCompInfo scriptblock

    # start Clear-Jobs function
    Function Clear-Jobs {
        Get-Job | Wait-Job
        Get-Job | Stop-Job
        Get-Job | Remove-Job
    } # end Clear-Jobs function

    # start timer scriptblock
    $timerScript = {
        param (
            $Timeout,
            $compInfoJob
        )
        $compInfoJob | Wait-Job -Timeout $Timeout
        $compInfoJob | Stop-Job
        $compInfoJob | Remove-Job
    } # end timer scriptblock

    # initialize WindowsHosts object
    $windowsHosts = [PSCustomObject]@{}

    # process each chunk of computer names
    foreach ($chunk in $chunks) {
        Clear-Jobs

        Write-Host -ForegroundColor Green "Processing new chunk"

        foreach ($computerName in $chunk) {
            $computerName = $($computerName.Name)
            Write-Host -ForegroundColor Cyan "Processing computer: $computerName"
            $compInfoJob  = Start-ThreadJob -ScriptBlock $GetCompInfo -ThrottleLimit $ThrottleLimit -ArgumentList $computerName, $GetUserDeviceAffinity, $windowsHosts, $outputPath, $appx, $drivers
            $timerJob     = Start-ThreadJob -ScriptBlock $timerScript -ArgumentList $Timeout, $compInfoJob
        }
    }
    Clear-Jobs
} # end function Get-ComputerInfo

$elapsedTime = Measure-Command {
    Get-ComputerInfo -computerList $computerList -Timeout $Timeout -ThrottleLimit $ThrottleLimit -outputPath $outputPath #-appx $true -drivers $true -GetUserDeviceAffinity $GetUserDeviceAffinity
}

Write-Host $elapsedTime
