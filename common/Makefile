# common Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c -lgmp -lgmpxx
debug: BFLAGS += -g
debug: all

all: includes.o

includes.o: includes.h includes.cpp
	$(CC) $(CFLAGS) includes.cpp

clean:
	rm -f *.o
