# RNG Makefile
CC=g++
LFLAGS= -lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: BBS.o MillerRabin.o mt19937.o

BBS.o: BBS.h BBS.cpp ../common/cryptomath.h primalitytest.h
	$(CC) $(CFLAGS) BBS.cpp $(LFLAGS)

clean:
	rm -f *.o
