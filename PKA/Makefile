# PKA Makefile
CXX?=g++
LDFLAGS=-lgmp -lgmpxx
CXXFLAGS=-std=c++11 -Wall -c

debug: CXXFLAGS += -g
debug: all

all: PKA.o DSA.o ElGamal.o RSA.o

PKA.o: PKA.h PKA.cpp DSA.h ElGamal.h RSA.h
	$(CXX) $(CXXFLAGS) PKA.cpp

DSA.o: DSA.h DSA.cpp ../common/cryptomath.h ../Hashes/Hashes.h ../RNG/RNG.h
	$(CXX) $(CXXFLAGS) DSA.cpp

ElGamal.o: ElGamal.h ElGamal.cpp ../RNG/RNG.h
	$(CXX) $(CXXFLAGS) ElGamal.cpp

RSA.o: RSA.h RSA.cpp ../consts.h ../common/includes.h ../RNG/RNG.h
	$(CXX) $(CXXFLAGS) RSA.cpp

clean:
	rm -f *.o
