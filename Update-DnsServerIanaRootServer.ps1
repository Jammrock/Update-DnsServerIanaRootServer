# Update the Windows DNS server root [hints] server addresses directly from IANA.
#requires -Modules DnsServer

using namespace System.Collections.Generic

<#
.SYNOPSIS 
    Retrieves the root server list from IANA, and then uses that list to ensure the Windows DNS server has all servers and IP addresses.

.DESCRIPTION
    Retrieves the root server list from IANA, and then uses that list to ensure the Windows DNS server has all servers and IP addresses. Both IPv4 and IPv6 addresses are updated, by default. Use the IPv4Only and IPv6Only parameters to limit the update to a single address family.

#>

[CmdletBinding()]
param (
    # Checks and updates the root server IPv4 addresses.    
    [Parameter()]
    [switch]
    $IPv4Only,

    # Checks and updates the root server IPv6 addresses.    
    [Parameter()]
    [switch]
    $IPv6Only,

    # Removes an existing root hint and replace it with the root server data returned from IANA.
    [Parameter()]
    [switch]
    $ForceIana
)

begin {
    Write-Verbose "Begin"
    # this function parses the named.root file
    function Convert-RootZone2Object {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]
            $rootZoneFile
        )

        Write-Verbose "Convert-RootZone2Object - Begin"
        # create the list
        $root = [List[PSCustomObject]]::new()

        # do the work
        $rootZoneFile -split "\r?\n"  | & { process {
            # filter by matching lines, ignoring the the NS record lines
            if ($_ -match "^((?<host>\.)|(?<host>\.|\w\.ROOT-SERVERS\.NET\.))\s+(?<ttl>\d{1,8})\s+((?<type>NS)|(?<type>A{1,4}))\s+(?<data>.*)$") {
                Write-Verbose "Convert-RootZone2Object - Found match: $_"
                try {
                    # save the data to variables
                    [string]$hostname = $Matches.host
                    $ttl = [int]::Parse($Matches.ttl)
                    [string]$type = $Matches.type
                    [string]$RecData = $Matches.data

                    # create the object
                    $obj = [PSCustomObject]@{
                        Name       = $hostname
                        TTL        = $ttl
                        Type       = $type
                        RecordData = $RecData
                    }
                    Write-Verbose "Convert-RootZone2Object - obj:`n$obj"

                    # add the object to the collection
                    $root.Add($obj)
                    Write-Verbose "Convert-RootZone2Object - Record added."
                } catch {
                    throw "Failed to parse the named.root file. Error: $_"
                }
            }
        }}

        Write-Verbose "Convert-RootZone2Object - Work complete. Returning $($root.Count) objects."
        return $root
    }

    # make sure DNS is installed
    Write-Verbose "Making sure DNS server is installed."
    $dnsServerState = Get-WindowsFeature DNS

    if ( -NOT $dnsServerState.Installed ) {
        throw "DNS server must be installed."
    }

    # URL to the IANA root servers file (HTTPS).
    $rootFileURL = 'https://www.internic.net/domain/named.root'
    Write-Verbose "rootFileURL: $rootFileURL"
    
    # try to retrieve the IANA root server list
    try {
        $rootZoneFile = Invoke-WebRequest $rootFileURL -SslProtocol Tls12 -UseBasicParsing
        Write-Verbose "named.root was retrieved."
    } catch {
        throw "Failed to download the root.zone file. Please make sure the server has HTTPS access to www.internic.net. Error: $_"
    }

    # parse the file to objects
    Write-Verbose "Getting the IANA root server list."
    $rootServers = Convert-RootZone2Object -rootZoneFile $rootZoneFile.Content

    # make sure there's an object
    if (-NOT $rootServers -or $rootServers.Count -eq 0) {
        throw "Failed to parse the named.root file."
    }

    # get the local root hints
    Write-Verbose "Collecting local root hints."
    $localHints = Get-DnsServerRootHint
}

process {
    Write-Verbose "Process"
    # create a list of all name servers
    $rootNames = $rootServers | Where-Object RecordData -match "ROOT-SERVERS.NET." | ForEach-Object RecordData | Sort-Object -Unique
    Write-Verbose "rootNames: $rootNames"

    # trust the IANA root servers so loop through those
    foreach ($name in $rootNames) {
        Write-Verbose "Validating $name"
        # get the matching local root hints, if available
        $localH = $localHints | Where-Object {$_.NameServer.RecordData.NameServer -eq $name}
        Write-Verbose "Matching local hints:`n$($localH | Format-List | Out-String)"

        # get the matching records from root servers
        $rootH = $rootServers | Where-Object {$_.Name -eq $name -and ($_.Type -eq "A" -or $_.Type -eq "AAAA")}
        Write-Verbose "Matching IANA root server:`n$($rootH | Format-List | Out-String)"

        # Force option: Remove the existing root hints and replace it with IANA named.root records.
        if ($ForceIana.IsPresent) {
            Write-Verbose "Forcing IANA root servers."
            # delete any matching root hints
            Write-Verbose "Removing $name root hints from DNS."
            $localH | Remove-DnsServerRootHint -Force -EA SilentlyContinue

            # add the IANA version back in 
            foreach ($rh in $rootH) {
                $rhIP = [ipaddress]::new(0)
                if (-NOT [ipaddress]::TryParse($rh.RecordData, [ref]$rhIP)) {
                    Write-Warning "Failed to parse the root hint IP address. addr: $($rh.RecordData)"
                    continue
                }

                $rhSplat = @{
                    NameServer = ($name.ToUpper())
                    IPAddress  = $rhIP
                }
                Write-Host -ForegroundColor Green "Adding the root hint: $name - $($rhIP.IPAddressToString)"
                Add-DnsServerRootHint @rhSplat
            }
        # Gap option: Fill in any missing root servers based on named.root, but do not remove anything.
        } elseif ( $localH ) {
            Write-Verbose "Looking for missing addresses."
            :nochange foreach ($rh in $rootH) {
                # determine whether to test and update the root hint record
                if ($IPv4Only.IsPresent -and $rh.Type -eq "A" -or
                     $IPv6Only.IsPresent -and $rh.Type -eq "AAAA" -or
                     (-NOT $IPv4Only.IsPresent -and -NOT $IPv6Only.IsPresent)) {

                    Write-Verbose "Processing:`n$($rh | Format-List | Out-String)"

                    $rhIP = [ipaddress]::new(0)
                    if (-NOT [ipaddress]::TryParse($rh.RecordData, [ref]$rhIP)) {
                        Write-Warning "Failed to parse the root hint IP address. addr: $($rh.RecordData)"
                        continue
                    }
                    
                    # compare the IANA hint to the local hint
                    if ($rh.Type -eq "A") {
                        # check for a local A RR
                        [array]$localA = $localH.IPAddress | Where-Object {$_.RecordType -eq "A"} | ForEach-Object {$_.RecordData.IPv4Address.IPAddressToString }

                        Write-Verbose "Does $($localA -join ',') contain $($rhIP)"
                        # look for an A local A record
                        if ( $localA -contains $rhIP.IPAddressToString ) {
                            Write-Verbose "IPv4 found locally, no change needed."
                            continue nochange
                        }
                    } elseif ($rh.Type -eq "AAAA") {
                        [array]$localAAAA = $localH.IPAddress | Where-Object {$_.RecordType -eq "AAAA"} | ForEach-Object {$_.RecordData.IPv6Address.IPAddressToString }

                        Write-Verbose "Does $($localAAAA -join ',') contain $($rhIP))"
                        if ( $localAAAA -contains $rhIP.IPAddressToString ) {
                            Write-Verbose "IPv6 found locally, no change needed."
                            continue nochange
                        }
                    } else {
                        Write-Verbose "Unsupported record type."
                        continue
                    }

                    # a change is needed... do it
                    $rhSplat = @{
                        NameServer = ($name.ToUpper())
                        IPAddress  = $rhIP
                    }
                    Write-Host -ForegroundColor Green "Adding the missing A address: $name - $($rhIP.IPAddressToString)"
                    Add-DnsServerRootHint @rhSplat
                }
            }
        # Missing root option: the root hint servers is missing from the local list, so add it.
        } else {
            Write-Verbose "$name was not found locally."
            # process the local root servers against the IANA root servers
            if ($IPv4Only.IsPresent -and $rh.Type -eq "A" -or
                     $IPv6Only.IsPresent -and $rh.Type -eq "AAAA" -or
                     (-NOT $IPv4Only.IsPresent -and -NOT $IPv6Only.IsPresent)) {
                
                # add the missing records
                foreach ($rh in $rootH) {
                    $rhIP = [ipaddress]::new(0)
                    if (-NOT [ipaddress]::TryParse($rh.RecordData, [ref]$rhIP)) {
                        Write-Warning "Failed to parse the root hint IP address. addr: $($rh.RecordData)"
                        continue
                    }

                    $rhSplat = @{
                        NameServer = ($name.ToUpper())
                        IPAddress  = $rhIP
                    }
                    Write-Host -ForegroundColor Green "Adding the missing root hint: $name - $($rhIP.IPAddressToString)"
                    Add-DnsServerRootHint @rhSplat
                }
            }
        }
    }
}

end {
    Write-Verbose "End"
    # no cleanup needed
}