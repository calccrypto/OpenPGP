# common Makefile
CXX?=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: includes.o

includes.o: includes.h includes.cpp
	$(CXX) $(CFLAGS) includes.cpp

clean:
	rm -f *.o
