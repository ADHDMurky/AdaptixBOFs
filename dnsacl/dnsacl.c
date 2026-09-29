/* Read-only AD DNS zone ACL inspection. No LDAP writes or credential handling. */
#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

typedef struct { char *original, *buffer; int length, size; } datap;
DECLSPEC_IMPORT void BeaconDataParse(datap *, char *, int);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *, int *);
DECLSPEC_IMPORT int BeaconDataInt(datap *);
DECLSPEC_IMPORT void BeaconPrintf(int, const char *, ...);
#undef OUT
#define OUT 0
#define ERR 13
#define IMPORT(lib, fn) DECLSPEC_IMPORT __typeof__(fn) lib##$##fn
IMPORT(WLDAP32, ldap_sslinitA);
IMPORT(WLDAP32, ldap_set_option);
IMPORT(WLDAP32, ldap_bind_sA);
IMPORT(WLDAP32, ldap_search_ext_sA);
IMPORT(WLDAP32, ldap_first_entry);
IMPORT(WLDAP32, ldap_next_entry);
IMPORT(WLDAP32, ldap_get_valuesA);
IMPORT(WLDAP32, ldap_get_values_lenA);
IMPORT(WLDAP32, ldap_value_freeA);
IMPORT(WLDAP32, ldap_value_free_len);
IMPORT(WLDAP32, ldap_get_dnA);
IMPORT(WLDAP32, ldap_memfreeA);
IMPORT(WLDAP32, ldap_msgfree);
IMPORT(WLDAP32, ldap_unbind);
IMPORT(WLDAP32, ldap_err2stringA);
IMPORT(ADVAPI32, ConvertSecurityDescriptorToStringSecurityDescriptorA);
IMPORT(ADVAPI32, ConvertSidToStringSidA);
IMPORT(KERNEL32, LocalFree);
IMPORT(KERNEL32, GetLastError);
IMPORT(KERNEL32, GetProcessHeap);
IMPORT(KERNEL32, HeapAlloc);
IMPORT(KERNEL32, HeapFree);
IMPORT(MSVCRT, memcpy);
IMPORT(MSVCRT, strcmp);
IMPORT(MSVCRT, strlen);
IMPORT(MSVCRT, _snprintf);
DECLSPEC_IMPORT BOOLEAN NTAPI NTDLL$RtlValidRelativeSecurityDescriptor(PSECURITY_DESCRIPTOR, ULONG, SECURITY_INFORMATION);

#define COPY MSVCRT$memcpy
#define FMT MSVCRT$_snprintf
#define EQ(a,b) (MSVCRT$strcmp((a),(b)) == 0)

typedef struct {
    LDAP *ld;
    char domainDN[1024];
    char forestDN[1024];
    char base[2048];
    char dnsNodeGuid[40];
    char dnsRecordGuid[40];
    unsigned zones;
} Context;

static void ldap_error(const char *operation, ULONG status) {
    BeaconPrintf(ERR, "%s: LDAP %lu (%s)", operation, status, WLDAP32$ldap_err2stringA(status));
}
static ULONG search(Context *c, char *base, ULONG scope, char *filter,
                    char **attrs, int dacl, LDAPMessage **result) {
    char der[] = {0x30, 0x03, 0x02, 0x01, 0x04}; /* SEQUENCE { INTEGER DACL_SECURITY_INFORMATION } */
    LDAPControlA control = {0};
    LDAPControlA *controls[2] = {&control, NULL};
    struct l_timeval timeout = {15, 0};
    control.ldctl_oid = "1.2.840.113556.1.4.801";
    control.ldctl_value.bv_len = sizeof(der);
    control.ldctl_value.bv_val = der;
    control.ldctl_iscritical = TRUE;
    *result = NULL;
    return WLDAP32$ldap_search_ext_sA(c->ld, base, scope, filter, attrs, 0,
                                    dacl ? controls : NULL, NULL, &timeout, 500, result);
}
static int get_text(Context *c, LDAPMessage *entry, char *attr, char *out, size_t size) {
    char **values = WLDAP32$ldap_get_valuesA(c->ld, entry, attr);
    int ok = 0;
    if (values && values[0] && MSVCRT$strlen(values[0]) < size) {
        FMT(out, size, "%s", values[0]);
        ok = 1;
    }
    if (values) WLDAP32$ldap_value_freeA(values);
    return ok;
}
static void guid_text(const void *data, char out[40]) {
    GUID g;
    COPY(&g, data, sizeof(g));
    FMT(out, 40, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        (unsigned long)g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1],
        g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
}
static const char *guid_label(Context *c, const char *guid) {
    if (c->dnsNodeGuid[0] && EQ(guid, c->dnsNodeGuid)) return "dnsNode class";
    if (c->dnsRecordGuid[0] && EQ(guid, c->dnsRecordGuid)) return "dnsRecord attribute";
    return "unresolved GUID";
}
static void schema_guids(Context *c, char *schemaDN) {
    LDAPMessage *res = NULL, *entry;
    char *attrs[] = {"lDAPDisplayName", "schemaIDGUID", NULL};
    ULONG rc = search(c, schemaDN, LDAP_SCOPE_SUBTREE,
        "(|(lDAPDisplayName=dnsNode)(lDAPDisplayName=dnsRecord))", attrs, 0, &res);
    if (rc != LDAP_SUCCESS) ldap_error("Schema GUID lookup (continuing without names)", rc);
    if (res) {
        for (entry = WLDAP32$ldap_first_entry(c->ld, res); entry;
             entry = WLDAP32$ldap_next_entry(c->ld, entry)) {
            char name[64];
            struct berval **v = WLDAP32$ldap_get_values_lenA(c->ld, entry, "schemaIDGUID");
            if (v && v[0] && v[0]->bv_len == 16 && get_text(c, entry, "lDAPDisplayName", name, sizeof(name))) {
                if (EQ(name, "dnsNode")) guid_text(v[0]->bv_val, c->dnsNodeGuid);
                if (EQ(name, "dnsRecord")) guid_text(v[0]->bv_val, c->dnsRecordGuid);
            }
            if (v) WLDAP32$ldap_value_free_len(v);
        }
        WLDAP32$ldap_msgfree(res);
    }
    BeaconPrintf(OUT, "Schema: dnsNode=%s; dnsRecord=%s", c->dnsNodeGuid[0] ? c->dnsNodeGuid : "unresolved",
                 c->dnsRecordGuid[0] ? c->dnsRecordGuid : "unresolved");
}
static void print_ace(Context *c, ACE_HEADER *ace, unsigned index) {
    BYTE *start = (BYTE *)ace, *p, *end = start + ace->AceSize;
    DWORD mask, flags = 0;
    char obj[40] = "", inherited[40] = "";
    char *sid = NULL;
    int objectAce = ace->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE || ace->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE;
    int simpleAce = ace->AceType == ACCESS_ALLOWED_ACE_TYPE || ace->AceType == ACCESS_DENIED_ACE_TYPE;
    if (!objectAce && !simpleAce) {
        BeaconPrintf(OUT, "  ACE[%u] type=0x%02x flags=0x%02x: see SDDL (not simplified)", index, ace->AceType, ace->AceFlags);
        return;
    }
    if (ace->AceSize < 8) {
        BeaconPrintf(ERR, "  ACE[%u]: truncated access mask", index);
        return;
    }
    p = start + 8;
    COPY(&mask, start + 4, 4);
    if (objectAce) {
        if (end - p < 4) return;
        COPY(&flags, p, 4); p += 4;
        if (flags & ACE_OBJECT_TYPE_PRESENT) {
            if (end - p < 16) return;
            guid_text(p, obj); p += 16;
        }
        if (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            if (end - p < 16) return;
            guid_text(p, inherited); p += 16;
        }
    }
    if (end - p < 8 || p[0] != SID_REVISION || p[1] > SID_MAX_SUB_AUTHORITIES || end - p < 8 + 4 * p[1]) {
        BeaconPrintf(ERR, "  ACE[%u]: invalid SID bounds", index); return;
    }
    if (!ADVAPI32$ConvertSidToStringSidA((PSID)p, &sid)) {
        BeaconPrintf(ERR, "  SID conversion failed: %lu", KERNEL32$GetLastError()); return;
    }
    BeaconPrintf(OUT, "  ACE[%u] %s SID=%s mask=0x%08lx flags=0x%02x%s%s",
        index, (ace->AceType == ACCESS_DENIED_ACE_TYPE || ace->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) ? "DENY" : "ALLOW",
        sid, mask, ace->AceFlags, (ace->AceFlags & INHERITED_ACE) ? " INHERITED" : " EXPLICIT",
        (ace->AceFlags & INHERIT_ONLY_ACE) ? " INHERIT_ONLY (not this object)" : "");
    KERNEL32$LocalFree(sid);
    BeaconPrintf(OUT, "    Rights:%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        mask & 0x1 ? " CREATE_CHILD" : "", mask & 0x2 ? " DELETE_CHILD" : "",
        mask & 0x4 ? " LIST_CHILDREN" : "", mask & 0x8 ? " SELF" : "",
        mask & 0x10 ? " READ_PROPERTY" : "", mask & 0x20 ? " WRITE_PROPERTY" : "",
        mask & 0x40 ? " DELETE_TREE" : "", mask & 0x80 ? " LIST_OBJECT" : "",
        mask & 0x100 ? " CONTROL_ACCESS" : "", mask & DELETE ? " DELETE" : "",
        mask & READ_CONTROL ? " READ_CONTROL" : "", mask & WRITE_DAC ? " WRITE_DACL" : "",
        mask & WRITE_OWNER ? " WRITE_OWNER" : "", mask & GENERIC_ALL ? " GENERIC_ALL" : "");
    if ((mask & 0x000f01ff) == 0x000f01ff) BeaconPrintf(OUT, "    Includes mapped AD full-control rights");
    if (mask & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE))
        BeaconPrintf(OUT, "    Generic bits: READ=%u WRITE=%u EXECUTE=%u",
            !!(mask & GENERIC_READ), !!(mask & GENERIC_WRITE), !!(mask & GENERIC_EXECUTE));
    if (obj[0]) BeaconPrintf(OUT, "    ObjectType=%s (%s)", obj, guid_label(c, obj));
    else BeaconPrintf(OUT, "    ObjectType=unrestricted by GUID");
    if (inherited[0]) BeaconPrintf(OUT, "    InheritedObjectType=%s (%s)", inherited, guid_label(c, inherited));
}
static void print_sd(Context *c, struct berval *value) {
    SECURITY_DESCRIPTOR_RELATIVE *sd;
    ACL *acl;
    char *sddl = NULL;
    BYTE *p, *end;
    if (value->bv_len < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
        !NTDLL$RtlValidRelativeSecurityDescriptor(value->bv_val, value->bv_len, DACL_SECURITY_INFORMATION)) {
        BeaconPrintf(ERR, "Invalid/truncated self-relative security descriptor"); return;
    }
    sd = (SECURITY_DESCRIPTOR_RELATIVE *)value->bv_val;
    if (!(sd->Control & SE_SELF_RELATIVE)) { BeaconPrintf(ERR, "Descriptor is not self-relative"); return; }
    if (ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(sd, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &sddl, NULL)) {
        /* Chunk output so large descriptors do not depend on BeaconPrintf's buffer size. */
        size_t len = MSVCRT$strlen(sddl);
        BeaconPrintf(OUT, "SDDL (DACL only; concatenate numbered chunks):");
        for (size_t off = 0; off < len; off += 700)
            BeaconPrintf(OUT, "  SDDL[%lu] %.*s", (unsigned long)(off / 700), (int)((len-off > 700) ? 700 : len-off), sddl + off);
        KERNEL32$LocalFree(sddl);
    } else BeaconPrintf(ERR, "SDDL conversion failed: %lu", KERNEL32$GetLastError());
    if (!(sd->Control & SE_DACL_PRESENT)) { BeaconPrintf(OUT, "DACL absent; no DACL restriction (other controls may apply)"); return; }
    if (!sd->Dacl) { BeaconPrintf(OUT, "NULL DACL: unrestricted by DACL"); return; }
    if (sd->Dacl > value->bv_len - sizeof(ACL)) return;
    acl = (ACL *)((BYTE *)sd + sd->Dacl);
    if (acl->AclSize < sizeof(ACL) || acl->AclSize > value->bv_len - sd->Dacl) return;
    BeaconPrintf(OUT, "DACL ACEs=%u protected=%u", acl->AceCount, !!(sd->Control & SE_DACL_PROTECTED));
    if (!acl->AceCount) BeaconPrintf(OUT, "Empty DACL: grants no access");
    p = (BYTE *)acl + sizeof(ACL); end = (BYTE *)acl + acl->AclSize;
    for (unsigned i = 0; i < acl->AceCount; i++) {
        ACE_HEADER *ace = (ACE_HEADER *)p;
        if (end - p < (ptrdiff_t)sizeof(ACE_HEADER) || ace->AceSize < sizeof(ACE_HEADER) || ace->AceSize > end-p) {
            BeaconPrintf(ERR, "Invalid ACE bounds"); break;
        }
        print_ace(c, ace, i); p += ace->AceSize;
    }
}
static void inspect(Context *c, char *base, ULONG scope, char *filter) {
    LDAPMessage *res = NULL, *entry;
    char *attrs[] = {"nTSecurityDescriptor", NULL};
    BeaconPrintf(OUT, "Search base: %s", base);
    ULONG rc = search(c, base, scope, filter, attrs, 1, &res);
    if (rc != LDAP_SUCCESS) ldap_error(base, rc);
    if (res) {
        unsigned count = 0;
        for (entry = WLDAP32$ldap_first_entry(c->ld, res); entry;
             entry = WLDAP32$ldap_next_entry(c->ld, entry)) {
            char *dn = WLDAP32$ldap_get_dnA(c->ld, entry);
            struct berval **v = WLDAP32$ldap_get_values_lenA(c->ld, entry, "nTSecurityDescriptor");
            BeaconPrintf(OUT, "\nObject: %s", dn ? dn : "(DN unavailable)");
            if (v && v[0]) print_sd(c, v[0]);
            else BeaconPrintf(ERR, "nTSecurityDescriptor absent/not readable; not evidence of a missing DACL");
            if (v) WLDAP32$ldap_value_free_len(v);
            if (dn) WLDAP32$ldap_memfreeA(dn);
            count++; c->zones++;
        }
        BeaconPrintf(OUT, "Objects returned: %u%s", count, rc ? " (search not successful/complete)" : "");
        WLDAP32$ldap_msgfree(res);
    }
}
static int domain_dn(const char *domain, char out[1024]) {
    size_t n = MSVCRT$strlen(domain), pos = 0, start = 0;
    if (!n || n > 253) return 0;
    for (size_t i = 0; i <= n; i++) {
        unsigned char ch = (unsigned char)domain[i];
        if (!ch || ch == '.') {
            size_t len = i - start;
            if (!len || len > 63 || domain[start] == '-' || domain[i-1] == '-') return 0;
            int k = FMT(out + pos, 1024 - pos, "%sDC=%.*s", pos ? "," : "", (int)len, domain + start);
            if (k < 0 || (size_t)k >= 1024-pos) return 0;
            pos += k; start = i + 1;
        } else if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                     (ch >= '0' && ch <= '9') || ch == '-')) return 0;
    }
    return 1;
}
void go(char *args, int length) {
    datap parser;
    int domainLen = 0, dcLen = 0, dnLen = 0;
    BeaconDataParse(&parser, args, length);
    char *domain = BeaconDataExtract(&parser, &domainLen);
    char *dc = BeaconDataExtract(&parser, &dcLen);
    char *dn = BeaconDataExtract(&parser, &dnLen);
    int tls = BeaconDataInt(&parser);
    if (!domain || domainLen < 2 || domain[domainLen-1] || !dc || dcLen < 2 || dc[dcLen-1] ||
        !dn || dnLen < 1 || dn[dnLen-1]) {
        BeaconPrintf(ERR, "Expected packed cstr domain, cstr dc, cstr optional-DN, int ldaps"); return;
    }
    Context *c = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Context));
    if (!c) return;
    if (!domain_dn(domain, c->domainDN)) { BeaconPrintf(ERR, "Invalid DNS domain name"); goto done; }
    c->ld = WLDAP32$ldap_sslinitA(dc, tls ? 636 : 389, tls ? 1 : 0);
    if (!c->ld) { BeaconPrintf(ERR, "ldap_sslinitA failed"); goto done; }
    ULONG version = LDAP_VERSION3, yes = 1;
    ULONG rc = WLDAP32$ldap_set_option(c->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (rc != LDAP_SUCCESS) { ldap_error("LDAP version", rc); goto done; }
    rc = WLDAP32$ldap_set_option(c->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (rc != LDAP_SUCCESS) { ldap_error("Disable referrals", rc); goto done; }
    if (!tls) {
        rc = WLDAP32$ldap_set_option(c->ld, LDAP_OPT_SIGN, &yes);
        if (rc != LDAP_SUCCESS) { ldap_error("Require signing", rc); goto done; }
        rc = WLDAP32$ldap_set_option(c->ld, LDAP_OPT_ENCRYPT, &yes);
        if (rc != LDAP_SUCCESS) { ldap_error("Require sealing", rc); goto done; }
    }
    BeaconPrintf(OUT, "Read-only LDAP to %s:%d; current Windows credentials; referrals disabled", dc, tls ? 636 : 389);
    rc = WLDAP32$ldap_bind_sA(c->ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) { ldap_error("Bind", rc); goto done; }
    LDAPMessage *root = NULL;
    char *attrs[] = {"namingContexts", "rootDomainNamingContext", "schemaNamingContext", NULL};
    rc = search(c, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &root);
    if (rc != LDAP_SUCCESS) ldap_error("RootDSE", rc);
    if (root) {
        LDAPMessage *entry = WLDAP32$ldap_first_entry(c->ld, root);
        if (entry) {
            char **contexts = WLDAP32$ldap_get_valuesA(c->ld, entry, "namingContexts");
            if (contexts) {
                for (unsigned i = 0; contexts[i]; i++) BeaconPrintf(OUT, "Hosted naming context: %s", contexts[i]);
                WLDAP32$ldap_value_freeA(contexts);
            }
            get_text(c, entry, "rootDomainNamingContext", c->forestDN, sizeof(c->forestDN));
            if (get_text(c, entry, "schemaNamingContext", c->base, sizeof(c->base))) schema_guids(c, c->base);
        }
        WLDAP32$ldap_msgfree(root);
    }
    if (dn[0]) {
        inspect(c, dn, LDAP_SCOPE_BASE, "(objectClass=*)");
    } else {
        FMT(c->base, sizeof(c->base), "CN=MicrosoftDNS,DC=DomainDnsZones,%s", c->domainDN);
        inspect(c, c->base, LDAP_SCOPE_ONELEVEL, "(objectClass=dnsZone)");
        if (c->forestDN[0]) {
            FMT(c->base, sizeof(c->base), "CN=MicrosoftDNS,DC=ForestDnsZones,%s", c->forestDN);
            inspect(c, c->base, LDAP_SCOPE_ONELEVEL, "(objectClass=dnsZone)");
        } else BeaconPrintf(ERR, "Forest root unavailable; skipping ForestDnsZones (use --dn)");
        FMT(c->base, sizeof(c->base), "CN=MicrosoftDNS,CN=System,%s", c->domainDN);
        inspect(c, c->base, LDAP_SCOPE_ONELEVEL, "(objectClass=dnsZone)");
    }
    BeaconPrintf(OUT, "Done: %u objects. ACL inspection only, NOT an effective-access calculation.\n"
        "Consider group membership, deny order, object GUIDs, inherit-only flags and other controls.\n"
        "New names require CREATE_CHILD for dnsNode; existing names require appropriate dnsRecord write access.", c->zones);
done:
    if (c->ld) WLDAP32$ldap_unbind(c->ld);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, c);
}
