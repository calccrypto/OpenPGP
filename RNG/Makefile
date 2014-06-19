# RNG Makefile
CXX?=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: BBS.o

BBS.o: BBS.h BBS.cpp ../common/cryptomath.h ../pgptime.h
	$(CXX) $(CFLAGS) BBS.cpp

clean:
	rm -f *.o
