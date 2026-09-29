var metadata = {name: "DNS-Add", description: "Add-only AD DNS A records; preview by default"};
var cmd_dnsadd = ax.create_command("dnsadd", "Preview/create a NEW AD DNS A record using current credentials", "dnsadd lab.local --record test-host --data 192.0.2.10 --apply");
cmd_dnsadd.addArgFlagString("--record", "record", "Required: relative name or FQDN within the selected zone", "");
cmd_dnsadd.addArgFlagString("--data", "data", "Required: IPv4 address for the A record", "");
cmd_dnsadd.addArgFlagString("--zone", "zone", "Zone name; default is domain", "");
cmd_dnsadd.addArgFlagString("--ttl", "ttl", "TTL in seconds (1..86400)", "180");
cmd_dnsadd.addArgBool("--forest", "Use ForestDnsZones");
cmd_dnsadd.addArgBool("--legacy", "Use legacy CN=System DNS storage");
cmd_dnsadd.addArgBool("--ldaps", "Use LDAPS/636 with certificate validation instead of signed/sealed LDAP/389");
cmd_dnsadd.addArgBool("--apply", "Actually create the new DNS object; otherwise preview only");
// Adaptix checks arguments in registration order: flags MUST precede optional positionals.
cmd_dnsadd.addArgString("domain", false, "DNS domain; default is session domain with computer-domain fallback");
cmd_dnsadd.addArgString("dc", false, "Writable DNS/DC FQDN; discovered if omitted");
cmd_dnsadd.setPreHook(function (id, cmdline, p, ...parsed_lines) {
    let packed = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,int,int,int,int", [
        p["domain"] || "", p["dc"] || "", p["record"] || "", p["data"] || "", p["zone"] || "", p["ttl"] || "180",
        p["--ldaps"] ? 1 : 0, p["--forest"] ? 1 : 0, p["--legacy"] ? 1 : 0, p["--apply"] ? 1 : 0
    ]);
    let file = ax.script_dir() + "_bin/dnsadd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${file}" ${packed}`, p["--apply"] ? "Create new DNS A record (no overwrite)" : "Preview DNS A-record creation (no changes)");
});
var dnsadd_group = ax.create_commands_group("DNS-Add", [cmd_dnsadd]);
ax.register_commands_group(dnsadd_group, ["beacon", "gopher", "kharon"], ["windows"], []);
