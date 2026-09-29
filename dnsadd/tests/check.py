import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
for arch, prefix, machine in [('x64','x86_64-w64-mingw32','pe-x86-64'), ('x86','i686-w64-mingw32','pe-i386')]:
    obj = root / '_bin' / f'dnsadd.{arch}.o'
    header = subprocess.check_output([f'{prefix}-objdump', '-f', str(obj)], text=True)
    assert machine in header
    symbols = subprocess.check_output([f'{prefix}-nm', str(obj)], text=True)
    assert re.search(r'\bT _?go$', symbols, re.M)
    undefined = subprocess.check_output([f'{prefix}-nm', '-u', str(obj)], text=True)
    for line in undefined.splitlines():
        symbol = line.split()[-1]
        assert re.fullmatch(r'__imp__?(?:Beacon\w+|(?:DNSAPI|WLDAP32|MSVCRT|KERNEL32|NETAPI32|SECUR32)\$\w+)(?:@\d+)?', symbol), symbol
        assert not any(x in symbol for x in ['ldap_modify', 'ldap_delete', 'chkstk', 'stack_chk']), symbol
    assert 'ldap_add_ext_sA' in undefined
    print(f'PASS: {arch} COFF, entrypoint and imports (add-only, no modify/delete)')
with tempfile.TemporaryDirectory() as tmp:
    exe = pathlib.Path(tmp) / 'record-test'
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(root/'tests/record-test.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
print('PASS: native name/IP validation and MS-DNSP A-record binary layout')
subprocess.run(['node', str(root/'tests/axs-test.js')],check=True)
print('Windows/Adaptix/AD runtime NOT tested; no DNS changes were made by these tests.')
