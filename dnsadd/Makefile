CFLAGS = -Os -Wall -Wextra -Werror -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-builtin
.PHONY: all check clean
all: _bin/dnsadd.x64.o _bin/dnsadd.x86.o
_bin:
	mkdir -p $@
_bin/dnsadd.x64.o: dnsadd.c record.h | _bin
	x86_64-w64-mingw32-gcc $(CFLAGS) -c $< -o $@
_bin/dnsadd.x86.o: dnsadd.c record.h | _bin
	i686-w64-mingw32-gcc $(CFLAGS) -c $< -o $@
check: all
	python3 tests/check.py
clean:
	rm -f _bin/dnsadd.x64.o _bin/dnsadd.x86.o
