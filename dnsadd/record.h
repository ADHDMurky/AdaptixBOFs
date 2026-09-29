/* Pure helpers shared by the BOF and native tests. No platform APIs. */
#ifndef DNSADD_RECORD_H
#define DNSADD_RECORD_H
#include <stddef.h>
#include <stdint.h>

static int dns_name_valid(const char *s) {
    size_t label = 0, n = 0;
    if (!s || !*s) return 0;
    for (; s[n]; n++) {
        unsigned char ch = (unsigned char)s[n];
        if (n >= 253) return 0;
        if (ch == '.') {
            if (!label || s[n-1] == '-') return 0;
            label = 0;
        } else {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')) return 0;
            if ((!label && ch == '-') || ++label > 63) return 0;
        }
    }
    return label && s[n-1] != '-';
}
static int ipv4_parse(const char *s, unsigned char out[4]) {
    for (unsigned i = 0; i < 4; i++) {
        unsigned value = 0, count = 0;
        const char *begin = s;
        while (*s >= '0' && *s <= '9') {
            if (++count > 3) return 0;
            value = value * 10 + (unsigned)(*s++ - '0');
        }
        if (!count || value > 255 || (count > 1 && begin[0] == '0')) return 0;
        out[i] = (unsigned char)value;
        if (i < 3) { if (*s++ != '.') return 0; }
        else if (*s) return 0;
    }
    return 1;
}
static void le32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(value >> (8*i));
}
static void build_a_record(unsigned char out[28], const unsigned char ip[4], uint32_t serial, uint32_t ttl) {
    for (unsigned i = 0; i < 28; i++) out[i] = 0;
    out[0] = 4;            /* DataLength, little-endian uint16 */
    out[2] = 1;            /* DNS_TYPE_A, little-endian uint16 */
    out[4] = 5;            /* Version */
    out[5] = 240;          /* Authoritative rank */
    le32(out + 8, serial);
    for (unsigned i = 0; i < 4; i++) out[12+i] = (unsigned char)(ttl >> (24-8*i));
    /* Reserved, timestamp = 0 (static/non-aging record, like dnstool). */
    for (unsigned i = 0; i < 4; i++) out[24+i] = ip[i];
}
#endif
