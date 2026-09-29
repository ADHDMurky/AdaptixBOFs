/* Add-only A-record enrollment in AD DNS. Explicit --apply required.
 * No existing-node modification, deletion, ACL changes or supplied credentials. */
#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <windns.h>
#include <dsgetdc.h>
#include <lm.h>
#define SECURITY_WIN32
#include <security.h>
#include <secext.h>
#include <stdio.h>
#include <string.h>
#include "record.h"

typedef struct { char *original, *buffer; int length, size; } datap;
DECLSPEC_IMPORT void BeaconDataParse(datap *, char *, int);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *, int *);
DECLSPEC_IMPORT int BeaconDataInt(datap *);
DECLSPEC_IMPORT void BeaconPrintf(int, const char *, ...);
#define O 0
#define E 13
#define IMPORT(lib, fn) DECLSPEC_IMPORT __typeof__(fn) lib##$##fn
IMPORT(WLDAP32, ldap_sslinitA);
IMPORT(WLDAP32, ldap_set_option);
IMPORT(WLDAP32, ldap_bind_sA);
IMPORT(WLDAP32, ldap_search_ext_sA);
IMPORT(WLDAP32, ldap_first_entry);
IMPORT(WLDAP32, ldap_get_valuesA);
IMPORT(WLDAP32, ldap_value_freeA);
IMPORT(WLDAP32, ldap_msgfree);
IMPORT(WLDAP32, ldap_unbind);
IMPORT(WLDAP32, ldap_err2stringA);
IMPORT(WLDAP32, ldap_add_ext_sA);
IMPORT(NETAPI32, DsGetDcNameA);
IMPORT(NETAPI32, NetApiBufferFree);
IMPORT(SECUR32, GetUserNameExA);
IMPORT(DNSAPI, DnsQuery_A);
IMPORT(DNSAPI, DnsFree);
IMPORT(KERNEL32, GetProcessHeap);
IMPORT(KERNEL32, HeapAlloc);
IMPORT(KERNEL32, HeapFree);
IMPORT(MSVCRT, _snprintf);
IMPORT(MSVCRT, strlen);
IMPORT(MSVCRT, _stricmp);
IMPORT(MSVCRT, _strnicmp);
#define FMT MSVCRT$_snprintf
#define LEN MSVCRT$strlen

typedef struct {
    LDAP *ld;
    char identity[512], autoDomain[512];
    char domainDN[1024], forestDN[1024], schemaDN[1024];
    char zoneDN[1536], recordDN[2048], category[1152];
    char relative[254], fqdn[254];
    unsigned char ip[4], wire[28];
} State;

static void err(const char *where, ULONG code) {
    BeaconPrintf(E, "%s: LDAP %lu (%s)", where, code, WLDAP32$ldap_err2stringA(code));
}
static ULONG query(State *s, char *base, char *filter, char **attrs, LDAPMessage **result) {
    struct l_timeval timeout = {15, 0};
    *result = NULL;
    return WLDAP32$ldap_search_ext_sA(s->ld, base, LDAP_SCOPE_BASE, filter, attrs,
                                    0, NULL, NULL, &timeout, 2, result);
}
static int text(State *s, LDAPMessage *entry, char *attr, char *out, size_t size) {
    char **v = WLDAP32$ldap_get_valuesA(s->ld, entry, attr);
    int ok = 0;
    if (v && v[0] && LEN(v[0]) < size) { FMT(out, size, "%s", v[0]); ok = 1; }
    if (v) WLDAP32$ldap_value_freeA(v);
    return ok;
}
static int exists(State *s, char *dn, char *filter) {
    char *attrs[] = {"1.1", NULL};
    LDAPMessage *res = NULL;
    ULONG rc = query(s, dn, filter, attrs, &res);
    int found = -1;
    if (rc == LDAP_SUCCESS) found = res && WLDAP32$ldap_first_entry(s->ld, res) ? 1 : 0;
    else if (rc == LDAP_NO_SUCH_OBJECT) found = 0;
    else err("Existence check", rc);
    if (res) WLDAP32$ldap_msgfree(res);
    return found;
}
static void domain_dn(const char *domain, char out[1024]) {
    size_t start = 0, pos = 0;
    for (size_t i = 0; ; i++) {
        if (!domain[i] || domain[i] == '.') {
            int n = FMT(out + pos, 1024 - pos, "%sDC=%.*s", pos ? "," : "", (int)(i-start), domain+start);
            pos += n; start = i+1;
            if (!domain[i]) break;
        }
    }
}
static int next_serial(const char *dc, const char *zone, DWORD *serial) {
    DNS_RECORDA *records = NULL;
    IP4_ARRAY servers = {0};
    /* Resolve DC via the host resolver, then direct the SOA request to that DC. */
    DNS_STATUS rc = DNSAPI$DnsQuery_A(dc, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &records, NULL);
    if (rc == ERROR_SUCCESS) {
        for (DNS_RECORDA *p = records; p; p = p->pNext) {
            if (p->wType == DNS_TYPE_A) { servers.AddrCount = 1; servers.AddrArray[0] = p->Data.A.IpAddress; break; }
        }
    }
    if (records) DNSAPI$DnsFree(records, DnsFreeRecordList);
    if (!servers.AddrCount) {
        BeaconPrintf(E, "Cannot resolve an IPv4 DNS-server address for DC %s (DNS status %ld)", dc, (long)rc); return 0;
    }
    records = NULL;
    rc = DNSAPI$DnsQuery_A(zone, DNS_TYPE_SOA, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_WIRE_ONLY,
                         &servers, &records, NULL);
    int found = 0;
    if (rc == ERROR_SUCCESS) {
        for (DNS_RECORDA *p = records; p; p = p->pNext) {
            if (p->wType == DNS_TYPE_SOA && p->pName && !MSVCRT$_stricmp(p->pName, zone)) {
                *serial = p->Data.SOA.dwSerialNo + 1; found = 1; break;
            }
        }
    }
    if (records) DNSAPI$DnsFree(records, DnsFreeRecordList);
    if (!found) BeaconPrintf(E, "No matching SOA from DC for zone %s (DNS status %ld). Nothing added.", zone, (long)rc);
    return found;
}
static ULONG add_node(State *s) {
    char *classes[] = {"top", "dnsNode", NULL};
    char *category[] = {s->category, NULL};
    char *name[] = {s->relative, NULL};
    char *tombstone[] = {"FALSE", NULL};
    struct berval record = {sizeof(s->wire), (char *)s->wire};
    struct berval *binary[] = {&record, NULL};
    LDAPModA mods[5] = {0};
    LDAPModA *list[] = {&mods[0], &mods[1], &mods[2], &mods[3], &mods[4], NULL};
    mods[0].mod_op = LDAP_MOD_ADD; mods[0].mod_type = "objectClass"; mods[0].mod_values = classes;
    mods[1].mod_op = LDAP_MOD_ADD; mods[1].mod_type = "objectCategory"; mods[1].mod_values = category;
    mods[2].mod_op = LDAP_MOD_ADD; mods[2].mod_type = "name"; mods[2].mod_values = name;
    mods[3].mod_op = LDAP_MOD_ADD; mods[3].mod_type = "dNSTombstoned"; mods[3].mod_values = tombstone;
    mods[4].mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES; mods[4].mod_type = "dnsRecord"; mods[4].mod_bvalues = binary;
    return WLDAP32$ldap_add_ext_sA(s->ld, s->recordDN, list, NULL, NULL);
}
void go(char *args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);
    char *strings[6];
    for (unsigned i = 0; i < 6; i++) {
        int n = 0;
        strings[i] = BeaconDataExtract(&parser, &n);
        if (!strings[i] || n < 1 || strings[i][n-1]) { BeaconPrintf(E, "Invalid arguments; reload matching dnsadd.axs"); return; }
    }
    char *domain = strings[0], *dc = strings[1], *record = strings[2], *data = strings[3], *zone = strings[4], *ttlText = strings[5];
    int tls = BeaconDataInt(&parser), forest = BeaconDataInt(&parser), legacy = BeaconDataInt(&parser), apply = BeaconDataInt(&parser);
    if (!record[0] || !data[0]) { BeaconPrintf(E, "Required: --record <name> --data <IPv4>. Add --apply to write; default is preview."); return; }
    if (forest && legacy) { BeaconPrintf(E, "Use only one of --forest or --legacy"); return; }
    DWORD ttl = 0;
    if (!ttlText[0] || LEN(ttlText) > 5) { BeaconPrintf(E, "TTL must be 1..86400 seconds"); return; }
    for (char *p = ttlText; *p; p++) {
        if (*p < '0' || *p > '9') { BeaconPrintf(E, "TTL must be decimal seconds"); return; }
        ttl = ttl*10 + (*p-'0');
    }
    if (!ttl || ttl > 86400) { BeaconPrintf(E, "TTL must be 1..86400 seconds"); return; }
    State *s = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(State));
    PDOMAIN_CONTROLLER_INFOA discovered = NULL;
    if (!s) return;
    if (!ipv4_parse(data, s->ip)) { BeaconPrintf(E, "--data must be a plain IPv4 address (no leading-zero octets)"); goto done; }
    ULONG n = sizeof(s->identity);
    if (SECUR32$GetUserNameExA(NameSamCompatible, s->identity, &n)) BeaconPrintf(O, "Identity: %s", s->identity);
    if (!domain[0]) {
        n = sizeof(s->autoDomain);
        if (SECUR32$GetUserNameExA(NameDnsDomain, s->autoDomain, &n)) {
            for (char *p = s->autoDomain; *p; p++) if (*p == '\\') { *p = 0; domain = s->autoDomain; break; }
        }
    }
    if (!domain[0] || !dc[0]) {
        DWORD rc = NETAPI32$DsGetDcNameA(NULL, domain[0] ? domain : NULL, NULL, NULL,
            DS_DIRECTORY_SERVICE_REQUIRED | DS_WRITABLE_REQUIRED | DS_RETURN_DNS_NAME | DS_IP_REQUIRED, &discovered);
        if (rc) { BeaconPrintf(E, "DC discovery failed: %lu; supply domain and actual DC FQDN", rc); goto done; }
        if (!domain[0]) { domain = discovered->DomainName; BeaconPrintf(O, "Using computer-domain fallback: %s", domain); }
        if (!dc[0]) { dc = discovered->DomainControllerName; while (*dc == '\\') dc++; }
    }
    if (!zone[0]) zone = domain;
    if (!dns_name_valid(domain) || !dns_name_valid(zone) || !dns_name_valid(record)) {
        BeaconPrintf(E, "Invalid domain/zone/record. Use DNS labels without trailing dots or DN metacharacters; apex/@ is unsupported."); goto done;
    }
    size_t rn = LEN(record), zn = LEN(zone);
    if (!MSVCRT$_stricmp(record, zone)) { BeaconPrintf(E, "Zone apex is unsupported; choose a new host name"); goto done; }
    if (rn > zn && record[rn-zn-1] == '.' && !MSVCRT$_stricmp(record+rn-zn, zone)) rn -= zn+1;
    if (!rn || rn+1+zn > 253) { BeaconPrintf(E, "Record FQDN too long or empty"); goto done; }
    FMT(s->relative, sizeof(s->relative), "%.*s", (int)rn, record);
    FMT(s->fqdn, sizeof(s->fqdn), "%s.%s", s->relative, zone);
    domain_dn(domain, s->domainDN);
    s->ld = WLDAP32$ldap_sslinitA(dc, tls ? 636 : 389, tls ? 1 : 0);
    if (!s->ld) { BeaconPrintf(E, "Cannot initialize LDAP"); goto done; }
    ULONG version = LDAP_VERSION3, yes = 1, rc;
    rc = WLDAP32$ldap_set_option(s->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (rc) { err("LDAP version", rc); goto done; }
    rc = WLDAP32$ldap_set_option(s->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (rc) { err("LDAP referrals", rc); goto done; }
    if (!tls) {
        rc = WLDAP32$ldap_set_option(s->ld, LDAP_OPT_SIGN, &yes);
        if (rc) { err("Require signing", rc); goto done; }
        rc = WLDAP32$ldap_set_option(s->ld, LDAP_OPT_ENCRYPT, &yes);
        if (rc) { err("Require sealing", rc); goto done; }
    }
    rc = WLDAP32$ldap_bind_sA(s->ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc) { err("Bind", rc); goto done; }
    LDAPMessage *res = NULL;
    char *attrs[] = {"schemaNamingContext", "rootDomainNamingContext", NULL};
    rc = query(s, "", "(objectClass=*)", attrs, &res);
    int rootOK = 0;
    if (!rc && res) {
        LDAPMessage *entry = WLDAP32$ldap_first_entry(s->ld, res);
        if (entry) {
            rootOK = text(s, entry, "schemaNamingContext", s->schemaDN, sizeof(s->schemaDN));
            if (forest) rootOK = text(s, entry, "rootDomainNamingContext", s->forestDN, sizeof(s->forestDN)) && rootOK;
        }
    }
    if (res) WLDAP32$ldap_msgfree(res);
    if (!rootOK) { if (rc) err("RootDSE", rc); else BeaconPrintf(E, "Required naming contexts unavailable"); goto done; }
    if (forest) FMT(s->zoneDN, sizeof(s->zoneDN), "DC=%s,CN=MicrosoftDNS,DC=ForestDnsZones,%s", zone, s->forestDN);
    else if (legacy) FMT(s->zoneDN, sizeof(s->zoneDN), "DC=%s,CN=MicrosoftDNS,CN=System,%s", zone, s->domainDN);
    else FMT(s->zoneDN, sizeof(s->zoneDN), "DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones,%s", zone, s->domainDN);
    FMT(s->recordDN, sizeof(s->recordDN), "DC=%s,%s", s->relative, s->zoneDN);
    FMT(s->category, sizeof(s->category), "CN=Dns-Node,%s", s->schemaDN);
    BeaconPrintf(O, "[%s] %s A %s (TTL %lu)\nDC: %s\nTarget: %s", forest ? "forest" : legacy ? "legacy" : "current domain",
        s->fqdn, data, ttl, dc, s->recordDN);
    if (exists(s, s->zoneDN, "(objectClass=dnsZone)") != 1) {
        BeaconPrintf(E, "Zone not found/readable on this DC. Nothing added."); goto done;
    }
    int present = exists(s, s->recordDN, "(objectClass=*)");
    if (present != 0) {
        if (present == 1) BeaconPrintf(E, "Name already exists (including tombstoned nodes). Refusing to modify it.");
        goto done;
    }
    DWORD serial = 0;
    if (!next_serial(dc, zone, &serial)) goto done;
    build_a_record(s->wire, s->ip, serial, ttl);
    if (!apply) {
        BeaconPrintf(O, "PREVIEW ONLY: no changes. Re-run with --apply to create this static A record. Preview does not prove write permission."); goto done;
    }
    rc = add_node(s);
    if (rc == LDAP_SUCCESS) BeaconPrintf(O, "AD object created successfully. DNS service loading/replication may take time; verify DNS resolution separately.");
    else {
        err("LDAP add", rc);
        if (rc == LDAP_ALREADY_EXISTS) BeaconPrintf(E, "Name appeared after preflight; existing object was not modified.");
        if (rc == LDAP_INSUFFICIENT_RIGHTS) BeaconPrintf(E, "Server denied creation. New dnsNode names require appropriate Create Child rights on the zone.");
    }
done:
    if (s->ld) WLDAP32$ldap_unbind(s->ld);
    if (discovered) NETAPI32$NetApiBufferFree(discovered);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, s);
}
