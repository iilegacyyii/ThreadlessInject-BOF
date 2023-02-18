BOFNAME := threadless-inject
CC_x64 := x86_64-w64-mingw32-gcc


all:
	$(CC_x64) -o dist/$(BOFNAME).o -c entry.c

clean:
	rm -f disk/$(BOFNAME).o