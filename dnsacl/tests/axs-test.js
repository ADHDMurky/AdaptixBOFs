const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
let hook, captured, packed, registered;
let architecture = 'x64';
const command = {
    addArgString() {}, addArgFlagString() {}, addArgBool() {},
    setPreHook(fn) { hook = fn; }
};
const ax = {
    create_command(name) { assert.equal(name, 'dnsacl'); return command; },
    bof_pack(types, values) { packed = {types, values}; return 'PACKED'; },
    arch() { return architecture; },
    script_dir() { return '/extensions/dnsacl/'; },
    execute_alias(...args) { captured = args; },
    create_commands_group(name, commands) { assert.equal(commands[0], command); return name; },
    register_commands_group(...args) { registered = args; }
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', 'dnsacl.axs'), 'utf8'), {ax});
assert(registered && hook);
hook('agent', 'dnsacl example.com dc.example.com', {domain:'example.com', dc:'dc.example.com'});
assert.equal(packed.types, 'cstr,cstr,cstr,int');
assert.equal(JSON.stringify(packed.values), JSON.stringify(['example.com','dc.example.com','',0]));
assert(captured[2].includes('/_bin/dnsacl.x64.o'));
architecture = 'x86';
hook('agent', 'dnsacl', {domain:'example.com',dc:'dc.example.com',dn:'DC=example.com,CN=MicrosoftDNS', '--ldaps':true});
assert.equal(packed.values[3], 1);
assert.equal(packed.values[2], 'DC=example.com,CN=MicrosoftDNS');
assert(captured[2].includes('/_bin/dnsacl.x86.o'));
console.log('AXS: syntax, registration, packing, arch selection and optional flags verified with mock API');
