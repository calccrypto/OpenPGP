# Compression Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

debug: CXXFLAGS += -g
debug: all

all: Compress.o pgpbzip2.o pgpzlib.o

.PHONY: clean

Compress.o: Compress.h Compress.cpp pgpbzip2.h pgpzlib.h
	$(CXX) $(CXXFLAGS) Compress.cpp

pgpbzip2.o: pgpbzip2.h pgpbzip2.cpp
	$(CXX) $(CXXFLAGS) pgpbzip2.cpp

pgpzlib.o: pgpzlib.h pgpzlib.cpp
	$(CXX) $(CXXFLAGS) pgpzlib.cpp

clean:
	rm -f *.o
