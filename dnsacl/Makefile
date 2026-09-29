CFLAGS = -Os -Wall -Wextra -Werror -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-builtin

.PHONY: all clean check
all: _bin/dnsacl.x64.o _bin/dnsacl.x86.o

_bin:
	mkdir -p $@

_bin/dnsacl.x64.o: dnsacl.c | _bin
	x86_64-w64-mingw32-gcc $(CFLAGS) -c $< -o $@

_bin/dnsacl.x86.o: dnsacl.c | _bin
	i686-w64-mingw32-gcc $(CFLAGS) -c $< -o $@

check: all
	python3 tests/check.py

clean:
	rm -f _bin/dnsacl.x64.o _bin/dnsacl.x86.o
