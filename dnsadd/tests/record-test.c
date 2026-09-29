#include <assert.h>
#include <string.h>
#include "../record.h"
int main(void) {
    unsigned char ip[4], wire[28];
    assert(ipv4_parse("192.0.2.10", ip));
    assert(!ipv4_parse("192.0.2.256", ip));
    assert(!ipv4_parse("192.0.2", ip));
    assert(!ipv4_parse("192.0.2.1.2", ip));
    assert(!ipv4_parse("192.0.02.1", ip));
    assert(!ipv4_parse("", ip));
    assert(!ipv4_parse("1..2.3", ip));
    assert(dns_name_valid("host.lab.local"));
    assert(dns_name_valid("_msdcs.lab.local"));
    assert(!dns_name_valid("@"));
    assert(!dns_name_valid("host,DC=other"));
    assert(!dns_name_valid("a\\b"));
    assert(!dns_name_valid("a..b"));
    assert(!dns_name_valid("-a.b"));
    assert(!dns_name_valid("a-.b"));
    assert(!dns_name_valid("host.lab.local."));
    char longName[256];
    memset(longName, 'a', sizeof(longName)); longName[64] = 0;
    assert(!dns_name_valid(longName));
    assert(ipv4_parse("192.0.2.10", ip));
    build_a_record(wire, ip, 0x12345678, 180);
    const unsigned char expected[28] = {
        4,0, 1,0, 5,240, 0,0, 0x78,0x56,0x34,0x12,
        0,0,0,180, 0,0,0,0, 0,0,0,0, 192,0,2,10
    };
    assert(!memcmp(wire, expected, sizeof(wire)));
    build_a_record(wire, ip, 0, 86400);
    assert(wire[12] == 0 && wire[13] == 1 && wire[14] == 0x51 && wire[15] == 0x80);
    return 0;
}
