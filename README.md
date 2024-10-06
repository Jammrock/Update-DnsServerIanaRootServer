# Update-DnsServerIanaRootServer
Update the Windows DNS server root [hints] server addresses directly from the IANA named.root file. The named.root file is retrieved at runtime.

> [!WARNING]  
> The DNS server MUST have HTTPS access to www.internic.net to work!

This hasn't been turned into a module yet, so literal paths must be used to call the script.

# Usage

## Update missing records

```powershell
.\Update-DnsServerIanaRootServer.ps1
```

This mode will fill in any missing IPv4 or IPv6 root hint records.

## Update IPv4

```powershell
.\Update-DnsServerIanaRootServer.ps1 -IPv4Only
```

This mode will only update missing IPv4 root hint records.

## Update IPv6

```powershell
.\Update-DnsServerIanaRootServer.ps1 -IPv6Only
```

This mode will only update missing IPv6 root hint records.

## Force IANA

```powershell
.\Update-DnsServerIanaRootServer.ps1 -ForceIana
```

This mode will remove any existing root-servers and replace it with the IANA root servers. This mode can be used to reset the root hints on Windows DNS servers to match the current IANA named.root file.
