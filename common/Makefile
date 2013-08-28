# common Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g -O0
debug: all

all: includes.o integer.o

includes.o: includes.h includes.cpp
	$(CC) $(CFLAGS) includes.cpp

integer.o: integer.h integer.cpp
	$(CC) $(CFLAGS) integer.cpp

clean:
	rm -f *.o