# Compression Algorithms Makefile
CXX?=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: compress.o bzip2.o zlib.o zip.o

compress.o: compress.h compress.cpp pgpbzip2.h pgpzlib.h pgpzip.h
	$(CXX) $(CFLAGS) compress.cpp -lbz2 -lz -lzip

bzip2.o: pgpbzip2.h pgpbzip2.cpp
	$(CXX) $(CFLAGS) pgpbzip2.cpp -lbz2

zlib.o: pgpzlib.h pgpzlib.cpp
	$(CXX) $(CFLAGS) pgpzlib.cpp -lz

zip.o: pgpzip.h pgpzip.cpp
	$(CXX) $(CFLAGS) pgpzip.cpp -lzip

clean:
	rm -f *.o
