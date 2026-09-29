#!/usr/bin/env python3
"""Build-artifact checks, not an AD integration test."""
import pathlib
import re
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
for arch, prefix, expected in [
    ('x64', 'x86_64-w64-mingw32', 'pe-x86-64'),
    ('x86', 'i686-w64-mingw32', 'pe-i386'),
]:
    obj = root / '_bin' / f'dnsacl.{arch}.o'
    headers = subprocess.check_output([f'{prefix}-objdump', '-f', str(obj)], text=True)
    assert expected in headers, headers
    symbols = subprocess.check_output([f'{prefix}-nm', str(obj)], text=True)
    assert re.search(r'\bT _?go$', symbols, re.M), 'Missing BOF entrypoint'
    undefined = subprocess.check_output([f'{prefix}-nm', '-u', str(obj)], text=True)
    for line in undefined.splitlines():
        symbol = line.split()[-1]
        assert re.fullmatch(r'__imp__?(?:Beacon\w+|(?:ADVAPI32|KERNEL32|MSVCRT|NTDLL|WLDAP32)\$\w+)(?:@\d+)?', symbol), symbol
        assert not any(x in symbol for x in ['chkstk', 'stack_chk', 'ldap_modify', 'ldap_add', 'ldap_delete']), symbol
    print(f'{arch}: COFF type, entrypoint, imports verified')
subprocess.run(['node', str(root / 'tests' / 'axs-test.js')], check=True)
print('PASS: build/static and mocked AXS checks. Windows/AD runtime NOT tested.')
