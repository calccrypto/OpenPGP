# RNG Makefile
CXX?=g++
LDFLAGS=-lgmp -lgmpxx
CXXFLAGS=-std=c++11 -Wall -c
debug: CXXFLAGS += -g
debug: all

all: BBS.o

BBS.o: BBS.h BBS.cpp ../common/cryptomath.h ../pgptime.h
	$(CXX) $(CXXFLAGS) BBS.cpp

clean:
	rm -f *.o
