BOFNAME := threadless-inject
CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip

all:
	$(CC_x64) -o dist/$(BOFNAME).o -c entry.c -masm=intel -Wall
	$(STRIP_x64) --strip-unneeded dist/$(BOFNAME).o

clean:
	rm -f dist/$(BOFNAME).o
