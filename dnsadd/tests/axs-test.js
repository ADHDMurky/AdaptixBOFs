const fs = require('fs'), vm = require('vm'), path = require('path'), assert = require('assert');
let hook, packed, call, arch = 'x64';
const cmd = {addArgString(){}, addArgFlagString(){}, addArgBool(){}, setPreHook(f){hook=f;}};
const ax = {
    create_command(name){assert.equal(name, 'dnsadd'); return cmd;},
    create_commands_group(){return 'DNS-Add';}, register_commands_group(){},
    bof_pack(types, values){packed={types, values}; return 'ARGS';},
    script_dir(){return '/extensions/dnsadd/';}, arch(){return arch;},
    execute_alias(...args){call=args;}
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', 'dnsadd.axs'), 'utf8'), {ax});
hook('id', 'dnsadd', {record:'test-host', data:'192.0.2.10'});
assert.equal(packed.types, 'cstr,cstr,cstr,cstr,cstr,cstr,int,int,int,int');
assert.equal(JSON.stringify(packed.values), JSON.stringify(['','','test-host','192.0.2.10','','180',0,0,0,0]));
assert(call[2].includes('dnsadd.x64.o'));
assert(call[3].includes('no changes'));
arch = 'x86';
hook('id', 'dnsadd', {domain:'lab.local', dc:'dc01.lab.local', record:'test-host', data:'192.0.2.10', zone:'_msdcs.lab.local', ttl:'300', '--ldaps':true, '--forest':true, '--apply':true});
assert.equal(JSON.stringify(packed.values), JSON.stringify(['lab.local','dc01.lab.local','test-host','192.0.2.10','_msdcs.lab.local','300',1,1,0,1]));
assert(call[2].includes('dnsadd.x86.o'));
assert(call[3].includes('no overwrite'));
hook('id', 'dnsadd', {'--legacy':true});
assert.equal(packed.values[8], 1);
console.log('PASS: AXS defaults, preview/apply packing, flags and architecture selection');
