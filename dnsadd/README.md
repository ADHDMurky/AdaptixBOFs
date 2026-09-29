# dnsadd

Creates a new IPv4 A record in an existing Active Directory DNS zone using the
current Windows security context. Previews by default; `--apply` creates the record.
Existing names are never overwritten. Does not modify or delete records.

```text
dnsadd [domain] [dc] --record <name> --data <IPv4> [options]
```

| Parameter | Description |
| --- | --- |
| `domain` | Optional DNS domain. If omitted, attempts session-domain discovery, then computer-domain fallback. |
| `dc` | Optional domain controller FQDN. If omitted, discovers a writable DC. The selected DC must also serve DNS. |
| `--record` | Required new name: relative to the zone or an FQDN ending in that zone. Other dotted names are treated as relative. Apex (`@`), wildcards and trailing dots are unsupported. |
| `--data` | Required IPv4 address. Leading-zero octets are rejected. |
| `--zone` | Existing DNS zone. Defaults to `domain`, including when using `--forest`. |
| `--ttl` | TTL in seconds, from 1 to 86400. Default: 180. |
| `--forest` | Use ForestDnsZones instead of DomainDnsZones. |
| `--legacy` | Use legacy DNS storage under CN=System. Cannot be combined with `--forest`. |
| `--ldaps` | Use LDAPS on port 636 with certificate validation. Default: LDAP on port 389 with signing and sealing requested. |
| `--apply` | Actually create the record. Without this flag, only preview and validation run; preview does not prove write permission. |

```text
dnsadd example.com dc01.example.com --record test-host --data 192.0.2.10
dnsadd example.com dc01.example.com --record test-host --data 192.0.2.10 --ttl 300 --apply
```
