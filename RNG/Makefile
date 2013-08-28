# RNG Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g -O0
debug: all

all: BBS.o MillerRabin.o mt19937.o

BBS.o: BBS.h BBS.cpp ../common/cryptomath.h primalitytest.h
	$(CC) $(CFLAGS) BBS.cpp

MillerRabin.o: MillerRabin.h MillerRabin.cpp ../common/cryptomath.h ../common/integer.h BBS.h mt19937.h
	$(CC) $(CFLAGS) MillerRabin.cpp

mt19937.o: mt19937.h mt19937.cpp ../common/includes.h
	$(CC) $(CFLAGS) mt19937.cpp

clean:
	rm -f *.o