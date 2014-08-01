# PKA Makefile
CXX?=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: PKA.o DSA.o ElGamal.o RSA.o

PKA.o: PKA.h PKA.cpp DSA.h ElGamal.h RSA.h
	$(CXX) $(CFLAGS) PKA.cpp

DSA.o: DSA.h DSA.cpp ../common/cryptomath.h ../Hashes/Hashes.h ../RNG/RNG.h
	$(CXX) $(CFLAGS) DSA.cpp

ElGamal.o: ElGamal.h ElGamal.cpp ../RNG/RNG.h
	$(CXX) $(CFLAGS) ElGamal.cpp

RSA.o: RSA.h RSA.cpp ../consts.h ../common/includes.h ../RNG/RNG.h
	$(CXX) $(CFLAGS) RSA.cpp

clean:
	rm -f *.o
