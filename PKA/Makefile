# PKA Makefile
CC=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: DSA.o ElGamal.o RSA.o

DSA.o: DSA.h DSA.cpp ../common/cryptomath.h ../Hashes/Hashes.h ../RNG/RNG.h ../usehash.h
	$(CC) $(CFLAGS) $(LFLAGS) DSA.cpp

ElGamal.o: ElGamal.h ElGamal.cpp ../RNG/RNG.h
	$(CC) $(CFLAGS) $(LFLAGS) ElGamal.cpp

RSA.o: RSA.h RSA.cpp ../consts.h ../common/includes.h ../RNG/RNG.h ../usehash.h
	$(CC) $(CFLAGS) $(LFLAGS) RSA.cpp

clean:
	rm -f *.o
