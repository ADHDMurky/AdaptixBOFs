var metadata = {
    name: "DNS-ACL-ReadOnly",
    description: "Read-only AD DNS zone DACL/SDDL inspection"
};

var cmd_dnsacl = ax.create_command("dnsacl", "Read DNS zone DACLs and decode SDDL/ACEs (no effective-access claim)", "dnsacl dojo.local PT-DC01.dojo.local");
cmd_dnsacl.addArgString("domain", true, "DNS domain, e.g. dojo.local");
cmd_dnsacl.addArgString("dc", true, "Domain controller FQDN");
cmd_dnsacl.addArgFlagString("--dn", "dn", "Inspect one exact object DN instead of discovering standard DNS zones", "");
cmd_dnsacl.addArgBool("--ldaps", "Use LDAPS/636 with normal certificate validation; default is signed/sealed LDAP/389");
cmd_dnsacl.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr,int", [
        parsed_json["domain"], parsed_json["dc"], parsed_json["dn"] || "",
        parsed_json["--ldaps"] ? 1 : 0
    ]);
    let path = ax.script_dir() + "_bin/dnsacl." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${path}" ${params}`, "Read-only DNS zone ACL inspection");
});
var dnsacl_group = ax.create_commands_group("DNS-ACL-ReadOnly", [cmd_dnsacl]);
ax.register_commands_group(dnsacl_group, ["beacon", "gopher", "kharon"], ["windows"], []);
