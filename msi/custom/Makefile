CC64 = x86_64-w64-mingw32-gcc.exe
DLLWRAP64 = x86_64-w64-mingw32-dllwrap.exe

CC32 = gcc.exe
DLLWRAP32 = dllwrap.exe

all: seafile_custom32.dll seafile_custom64.dll

CFLAGS = -Wall -O2
DLLWRAPFLAGS = -Wl,--enable-stdcall-fixup

custom32.o: custom.c
	$(CC32) $(CFLAGS) custom.c -c -o $@

custom64.o: custom.c
	$(CC64) $(CFLAGS) custom.c -c -o $@

seafile_custom32.dll: custom32.o
	$(DLLWRAP32) $(DLLWRAPFLAGS) --def custom.def $< -o $@

seafile_custom64.dll: custom64.o
	$(DLLWRAP64) $(DLLWRAPFLAGS) --def custom.def $< -o $@

clean:
	rm -f *.o *.dll

install:
uninstall:
distclean:

.PHONY: all clean

