<#
.SYNOPSIS
    Retrieve System, Network, Application, Driver, and Primary user information 
    from all hosts in your domain - even if they may have WinRM, IIS, and PS-Remoting
    disabled by using PsExec of the Sysinternals suite.

.NOTES
    Name: Get-WinHostInfo-PsExec.ps1
    Author: Payton Flint
    Version: 1.3
    DateCreated: 2023-Aug

.LINK
    https://
#>

# Clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# Identify location of script
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent

# Filename for Get-UserDeviceAffinity script
$GetUserDeviceAffinity = "Get-UserDeviceAffinity.ps1"
# Build UNC path
$GetUserDeviceAffinity = "\\" + $env:COMPUTERNAME + '\' + $ScriptPath.Replace(':', '$') + '\' + $GetUserDeviceAffinity

# set output location for json file
$outputPath = Join-Path $scriptPath "WindowsHostsInfo.json"

# specify timeout & throttle limit (affects performance)
$TimeoutSeconds = '300'
$ThrottleLimit =  '8'

# get all computers from AD
$computerList = (Get-ADComputer -Filter * -Properties * | Where-Object -Property Enabled -EQ $True | Select-Object -Property Name | Sort-Object -Property Name).Name

# check for ThreadJob module, if not present, install
Function Install-Module {
    param (
        $name
    )
    $presence = Get-InstalledModule -Name $name -ErrorAction SilentlyContinue
        If (-not $presence) {
        Find-Module $name -ErrorAction SilentlyContinue | Install-Module -Force
    }
}
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
        Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:SystemRoot\System32\pstools"
        Move-Item -Path "$env:SystemRoot\System32\pstools\psexec.exe"
        Remove-Item -Path "$env:SystemRoot\System32\pstools" -Recurse
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            RegEdit -regPath "HKCU:\SOFTWARE\Sysinternals\PsExec" -regName "EulaAccepted" -regValue "1" -silent $true
        }
    }
} # End Function Install-PsExec
Install-PsExec -AcceptEULA $True

Function Get-ComputerInfo {
    param (
        $computerList,
        [int]$Timeout,
        [int]$ThrottleLimit,
        $outputPath,
        [bool]$drivers,        # only specify if desired (large dataset) 
        $GetUserDeviceAffinity # file path for Get-UserDeviceAffinity.ps1 (only specify if desired)
    )

    $GetCompInfo = {
        param (
            $computerName,
            $GetUserDeviceAffinity,
            $WindowsHosts,
            $outputPath
        )
        Function Convert-ToObjects {
            param (
                $inputString
            )
            # Split the input string into lines
            $lines = $inputString -split "`r?`n"

            # Initialize an empty array to hold objects
            $objects = @()
            # Initialize an empty hashtable to hold property values for the current application
            $properties = @{}

            # Iterate through each line and extract property and value using regex
            foreach ($line in $lines) {
                # Check if the line is empty or contains only whitespace
                if ([string]::IsNullOrWhiteSpace($line)) {
                    # If an empty line is encountered, create an object and add it to the array
                    if ($properties.Count -gt 0) {
                        $object = [PSCustomObject]$properties
                        $objects += $object
                        $properties = @{}  # Reset properties for the next application
                    }
                } elseif ($line -match '^(.*?):\s*(.*)$') {
                    # Use regex to split the line into property and value
                    $property = $matches[1].Trim()
                    $value = $matches[2].Trim()

                    if ($property -ne '') {
                        $properties[$property] = $value
                    }
                }
            }
            # If there are properties left, create the last object and add it to the array
            if ($properties.Count -gt 0) {
                $object = [PSCustomObject]$properties
                $objects += $object
            }
            # Return the resulting objects
            Write-Output $objects
        } # End Function Convert-ToObjects
            
        # initial run w/ PsExec
        $compInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-ComputerInfo" 2> $null
        $compInfo = Convert-ToObjects -inputString $compInfo

        # use Get-ComputerInfo as litmus test for whether device is responsive & Windows OS
        # further actions are contingent on Get-ComputerInfo results (increases performance)
        if ($compInfo) {
            # get network info & convert to objects
            $netInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-NetIPConfiguration" 2> $null
            $netInfo = Convert-ToObjects -inputString $netInfo
            # get application info & convert to objects
            $appInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-WmiObject -Class Win32_Product" 2> $null
            $appInfo = Convert-ToObjects -inputString $appInfo
            # create output object w/ above objects
            $output = [PSCustomObject]@{
                    System       = $compInfo
                    Network      = $netInfo
                    Applications = $appInfo
            }
            # if drivers is specified, get driver info, convert to objects, and add to output
            if ($drivers) {
                $driverInfo = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -Command "Get-WmiObject -Class Win32_PnPSignedDriver" 2> $null
                $driverInfo = Convert-ToObjects -inputString $driverInfo
                $output | Add-Member -MemberType NoteProperty -Name "Drivers" -Value $driverInfo
            }
            # if GetUserDeviceAffinity param is specified, add primary user property
            if ($GetUserDeviceAffinity) {
                $primaryUser = psexec.exe -s -nobanner -h \\$computerName Powershell.exe -NoInteractive -ExecutionPolicy Bypass -File "$GetUserDeviceAffinity" 2> $null
                $primaryUser = Convert-ToObjects -inputString $primaryUser
                $output | Add-Member -MemberType NoteProperty -Name "PrimaryUser" -Value $primaryUser
            }

            # Add output to WindowsHosts & export to .json output file
            $windowsHosts | Add-Member -MemberType NoteProperty -Name $computerName -Value $output
            $windowsHosts | ConvertTo-Json -depth 100 | Out-File "$outputPath" -Force
        }
    } # end GetCompInfo scriptblock

    # initialize WindowsHosts object
    $windowsHosts = [PSCustomObject]@{}

    # foreach computer, start jobs & timeout
    $computerList | ForEach-Object {
        $compInfoJob  = Start-ThreadJob -ScriptBlock $GetCompInfo -ThrottleLimit $ThrottleLimit -ArgumentList $_, $GetUserDeviceAffinity, $windowsHosts, $outputPath
    }
    # wait for specified timeout
    Get-Job | Wait-Job -Timeout $Timeout
    # clean up jobs
    Get-Job | Stop-Job
    Get-Job | Remove-Job

} # End Function Get-ComputerInfo

$elapsedTime = Measure-Command {
    Get-ComputerInfo -computerList $computerList -Timeout $TimeoutSeconds -ThrottleLimit $ThrottleLimit -outputPath $outputPath #-GetUserDeviceAffinity $GetUserDeviceAffinity
}

Write-Host -ForegroundColor Cyan $elapsedTime
