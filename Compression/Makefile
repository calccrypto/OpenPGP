# Compression Algorithms Makefile
CC=g++
LFLAGS=-lz -lbz2
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: #zip.o zlib.o bzip2.o

#zip.o: pgpzip.h pgpzip.cpp
#	$(CC) $(CFLAGS) pgpzip.cpp

#zlib.o: pgpzlib.h pgpzlib.cpp
#	$(CC) $(CFLAGS) pgpzlib.cpp

#bzip2.o: pgpbzip2.h pgpbzip2.cpp
#	$(CC) $(CFLAGS) pgpbzip2.cpp

clean:
	rm -f *.o
