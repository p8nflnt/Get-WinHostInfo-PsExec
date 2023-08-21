<#
.SYNOPSIS
    Get Primary User information for a domain-joined computer
    by means of EventLog analysis.
    Not to be confused w/ ConfigMan's Get-CMUserDeviceAffinity.

.NOTES
    Name: Get-UserDeviceAffinity
    Author: Payton Flint
    Version: 1.1
    DateCreated: 2023-August

.LINK
    https://paytonflint.com/powershell-programmatically-determine-the-primary-user-of-a-device/
    https://github.com/p8nflnt/SysAdmin-Toolbox/blob/main/Get-UserDeviceAffinity.ps1
#>

Function Get-UserDeviceAffinity {
    param (
        $ComputerName,
        [int]$MaxEvents,
        [bool]$PsExec
    )
    # get session info for logon event
    function Get-SessionInfo {
        param (
            $logonEvent
        )
        # get TargetLogonID value from event properties 
        $logonID = $logonEvent.Properties[7].Value

        # Construct the XPath filter for event 4634 with the specified Logon ID
        $xPathFilter = @"
        <QueryList>
          <Query Id="0" Path="Security">
            <Select Path="Security">
              *[System[(EventID=4634 or EventID=4647)]]
              and
              *[EventData[Data[@Name='TargetLogonId']='$logonID']]
            </Select>
          </Query>
        </QueryList>
"@ # end Here-String filter

        # Get logoff events matching above filter
        $logoffEvent = Get-WinEvent -LogName Security -FilterXPath $xPathFilter -ErrorAction SilentlyContinue
    
        # Get logoff events matching above filter
        if ($logoffEvent) {
            $duration = $logoffEvent.TimeCreated - $_.TimeCreated
            $duration = $duration.TotalMilliseconds

            # filter for events greater than 1 second
            if ($duration -gt '1000'){
                # create session object
                $session = [PSCustomObject]@{
                    Username   = $_.Properties[5].Value
                    LogonTime  = $_.TimeCreated
                    LogoffTime = $logoffEvent.TimeCreated
                    Duration   = $duration
                }
            Write-Output $session
            }
        }
    } # End Function Get-SessionInfo

    If ($ComputerName -ne $null) {
        # maximum events to pull w/ Get-WinEvent instances, affects performance
        $MaxEvents = 3200

        # get all logon events
        $logonEvents =  Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4624 } -MaxEvents $MaxEvents

        # create array for filtered logon events
        $filteredLogons = @()

        # get logons meeting criteria
        $logonEvents | ForEach-Object {
            If ($_.Properties[8].Value -in '2','7','10','11' -and $_.Properties[9].Value -like "User32*" `
            -and $_.Properties[12].Value -eq '00000000-0000-0000-0000-000000000000') {
                # add matches to array
                $filteredLogons += $_
            }
        }

        # get session info for all filtered logon events
        $sessions = $filteredLogons | ForEach-Object {
            Get-SessionInfo -logonEvent $_
        }

        # group user sessions by account name
        $acctSessions = $sessions | Group-Object -Property Username | ForEach-Object {
            # create objects for groups
            [PSCustomObject]@{
                Username =  $_.Name
                Duration = ($_.Group | Measure-Object -Property Duration -Sum).Sum
            }
        }

        # get username of group with greatest duration 
        $primaryUser = ($acctSessions | Sort-Object -Property Duration -Descending)[0].Username

        # get AD user object
        $AdUser =   Get-AdUser -Filter {SamAccountName -eq $primaryUser} -ErrorAction SilentlyContinue

        # create hashtable for output
        $output = @{}
        $output["Username"] = $primaryUser
        $output["Name"] =     $AdUser.Name

        # if PsExec param is $True, return key-value pairs separated by a colon rather than objects
        # (to simplify conversion back to objects via RegEx)
        If ($PsExec) {
            $output = $output.GetEnumerator() | ForEach-Object {
                "{0}: {1}" -f $_.Key, $_.Value
            }
        }
            Write-Output $output
        } Else {
            Write-Output "ComputerName is null"
        }
} # end function Get-UserDeviceAffinity

# execute function on host and return key-value pairs
$PrimaryUser = Get-UserDeviceAffinity -ComputerName "$env:COMPUTERNAME" -PsExec $True
# return result
$PrimaryUser
