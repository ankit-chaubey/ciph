CC = clang
CFLAGS = -O3 -fPIC
LIBS = -lsodium

all: libciph.so

libciph.so: ciph.c ciph.h
	$(CC) $(CFLAGS) -shared ciph.c -o libciph.so $(LIBS)

clean:
	rm -f libciph.so
