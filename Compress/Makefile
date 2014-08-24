# Compression Algorithms Makefile
CXX?=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: compress.o bzip2.o zlib.o

compress.o: Compress.h Compress.cpp pgpbzip2.h pgpzlib.h
	$(CXX) $(CFLAGS) Compress.cpp

bzip2.o: pgpbzip2.h pgpbzip2.cpp
	$(CXX) $(CFLAGS) pgpbzip2.cpp

zlib.o: pgpzlib.h pgpzlib.cpp
	$(CXX) $(CFLAGS) pgpzlib.cpp

clean:
	rm -f *.o
