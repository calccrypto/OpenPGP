# RNG Makefile
CC=g++
LFLAGS= -lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: BBS.o MillerRabin.o mt19937.o

BBS.o: BBS.h BBS.cpp ../common/cryptomath.h primalitytest.h
	$(CC) $(CFLAGS) BBS.cpp $(LFLAGS)

MillerRabin.o: MillerRabin.h MillerRabin.cpp ../common/cryptomath.h BBS.h mt19937.h
	$(CC) $(CFLAGS) MillerRabin.cpp $(LFLAGS)

mt19937.o: mt19937.h mt19937.cpp ../common/includes.h
	$(CC) $(CFLAGS) mt19937.cpp $(LFLAGS)

clean:
	rm -f *.o
