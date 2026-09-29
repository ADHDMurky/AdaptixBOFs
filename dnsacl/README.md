# dnsacl

Queries Active Directory DNS object permissions using the current Windows security
context. Prints DACLs, SDDL and ACEs without changing anything. This shows configured
permissions, not a definitive calculation of a user's effective access.

```text
dnsacl <domain> <dc> [--dn <object-DN>] [--ldaps]
```

| Parameter | Description |
| --- | --- |
| `domain` | Required DNS domain, such as `example.com`. |
| `dc` | Required domain controller FQDN, such as `dc01.example.com`. |
| `--dn` | Inspect one exact object DN instead of searching standard domain, forest and legacy DNS zone locations. |
| `--ldaps` | Use LDAPS on port 636 with certificate validation. Default: LDAP on port 389 with signing and sealing requested. |

```text
dnsacl example.com dc01.example.com
dnsacl example.com dc01.example.com --dn "DC=example.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com" --ldaps
```
