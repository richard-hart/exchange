<# 
    .SYNOPSIS 
    Add IP address(es) to an existing receive connector on selected or all Exchange 2013 Servers

    Thomas Stensitzki 

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE  
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 

    Version 1.4, 2018-09-04

    Please send ideas, comments and suggestions to support@granikos.eu 

    .LINK 
    http://scripts.granikos.eu

    .DESCRIPTION 
    This script adds a given IP address to an existing Receive Connector or reads an
    input file to add more than one IP address to the an existing Receive Connector.
    The script creates a new child directory under the current location of the script.
    The script utilizes the directory as a log directory to store the current remote
    IP address ranges prior modification.
 
    .NOTES 
    Requirements 
    - Windows Server 2008 R2 SP1, Windows Server 2012 or Windows Server 2012 R2  
    - A txt file containing new remote IP address ranges, one per line
      Example:
      192.168.1.1
      192.168.2.10-192.168.2.20
      192.168.3.0/24
    
    Revision History 
    -------------------------------------------------------------------------------- 
    1.0 Initial community release 
    1.1 Sorting for Exchange servers added
    1.2 PowerShell hygiene
    1.3 PowerShell hygiene - Part II
    1.4 Support Mailbox role added (issue #4)

    .PARAMETER ConnectorName  
    Name of the connector the new IP addresses should be added to  

    .PARAMETER FileName
    Name of the input file name containing IP addresses

    .PARAMETER ViewEntireForest
    View entire Active Directory forest (default FALSE)
    
    .EXAMPLE 
    .\Add-ReceiveConnectorIpAddress.ps1 -ConnectorName -FileName D:\Scripts\ip.txt

    .EXAMPLE 
    .\Add-ReceiveConnectorIpAddress.ps1 -ConnectorName -FileName .\ip-new.txt -ViewEntireForest $true

#> 
param(
	[parameter(Mandatory=$true,HelpMessage='Name of the Receive Connector')]
	[string] $ConnectorName,
	[parameter(Mandatory=$true,HelpMessage='Name of the input file name containing IP addresses')]
	[string] $FileName,
  [boolean] $ViewEntireForest = $false
)

# Set-StrictMode -Version Latest

$tmpFileFolderName = 'ReceiveConnectorIpAddresses'
$tmpFileLocation = ''
# Timestamp for use in filename, adjust formatting to your regional requirements
$timeStamp = Get-Date -Format 'yyyy-MM-dd HHmmss'

# FUNCTIONS --------------------------------------------------

function Test-LogPath {
    $script:tmpFileLocation = Join-Path -Path $PSScriptRoot -ChildPath $tmpFileFolderName
    if(-not (Test-Path -Path $script:tmpFileLocation)) {
        Write-Verbose -Message 'New file folder created'
        New-Item -ItemType Directory -Path $script:tmpFileLocation -Force | Out-Null
    }
}

function Test-ReceiveConnector {
    [CmdletBinding()]
    param(
        [string]$Server
    )

    Write-Verbose -Message ('Checking Server: {0}' -f $Server)

    # Fetch receive connector from server
    $targetRC = Get-ReceiveConnector -Server $Server | Where-Object{$_.name -eq $ConnectorName} -ErrorAction SilentlyContinue

    if($targetRC -ne $null) {
        Write-Verbose -Message ('Found connector {0} on server {1}' -f $ConnectorName, $Server)
	    Write-ConnectorIpRanges -ReceiveConnector $targetRC
    }
    else {
        Write-Output -InputObject ('INFO: Connector {0} NOT found on server {1}' -f $ConnectorName, $Server)
    }
}

function Write-ConnectorIpRanges {
    [CmdletBinding()]
    param (
        $ReceiveConnector
    )
    # Create a list of currently configured IP ranges 
    $tmpRemoteIpRanges = ''
    foreach ( $remoteIpRange in ($ReceiveConnector).RemoteIPRanges ) {
        $tmpRemoteIpRanges += ("`r`n{0}" -f $remoteIpRange)			
	}

    Write-Verbose -Message $tmpFileLocation
    
    # Save current remote IP ranges for connector to disk
    $fileIpRanges = (('{0}\{1}-{2}-Export.txt' -f $tmpFileLocation, $ConnectorName, $timeStamp)).ToUpper()
    Write-Verbose -Message ('Saving current IP ranges to: {0}' -f $fileIpRanges)
    Write-Output -InputObject $tmpRemoteIpRanges | Out-File -FilePath $fileIpRanges -Force -Encoding UTF8

    # Fetch new IP ranges from disk
    $newIpRangesFileContent = ''
    if(Test-Path -Path $FileName) {
	    Write-Verbose -Message ('Reading file {0}' -f $FileName)
	    $newIpRangesFileContent = Get-Content -Path $FileName
    }

    # add new IP ranges, if file exsists and had content
    if($newIpRangesFileContent -ne ''){
        foreach ($newIpRange in $newIpRangesFileContent ){
	        Write-Verbose -Message ('Checking new Remote IP range {0} in {1}' -f $newIpRange, $fileIpRanges)
            # Check if new remote IP range already exists in configure remote IP range of connector
	        $ipSearch = (Select-String -Pattern $newIpRange -Path $fileIpRanges )
	        if ($ipSearch -ne $null ){
                # Remote IP range exists, nothing to do here
                Write-Output -InputObject ('Remote IP range [{0}] already exists' -f $newIpRange)
		    }
		    else {
                # Remote IP range does not exist, add range to receive connector object
	            Write-Output -InputObject ('Remote IP range [{0}] will be added to {1}' -f $newIpRange, $ConnectorName) 
	            $ReceiveConnector.RemoteIPRanges += $newIpRange
	        }
        }
        # save changes to receive connector
        Set-ReceiveConnector -Identity $ReceiveConnector.Identity -RemoteIPRanges $ReceiveConnector.RemoteIPRanges | Sort-Object -Unique
    }    
}

# MAIN -------------------------------------------------------

if($ViewEntireForest) {
    Write-Verbose -Message ('Setting ADServerSettings -ViewEntireForest {0}' -f $true)
    Set-ADServerSettings -ViewEntireForets $true
}

Test-LogPath

# Fetch all Exchange 2013+ Servers
$allExchangeServers = Get-ExchangeServer | Where-Object{($_.AdminDisplayVersion.Major -eq 15) -and (([string]$_.ServerRole).Contains('ClientAccess') -or ([string]$_.ServerRole).Contains('Mailbox'))} | Sort-Object

foreach($Server in $AllExchangeServers) {
    Write-Output -InputObject ('Checking receive connector {0} on server {1}' -f $ConnectorName, $Server)
    Test-ReceiveConnector -Server $Server
}