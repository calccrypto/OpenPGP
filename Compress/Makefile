# Compression Algorithms Makefile
CXX?=g++
LDFLAGS=
CXXFLAGS=-std=c++11 -Wall -c

debug: CXXFLAGS += -g
debug: all

all: compress.o bzip2.o zlib.o

compress.o: Compress.h Compress.cpp pgpbzip2.h pgpzlib.h
	$(CXX) $(CXXFLAGS) Compress.cpp

bzip2.o: pgpbzip2.h pgpbzip2.cpp
	$(CXX) $(CXXFLAGS) pgpbzip2.cpp

zlib.o: pgpzlib.h pgpzlib.cpp
	$(CXX) $(CXXFLAGS) pgpzlib.cpp

clean:
	rm -f *.o
