# PKA Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g -O0
debug: all

all: DSA.o ElGamal.o RSA.o

DSA.o: DSA.h DSA.cpp ../common/cryptomath.h ../common/integer.h ../Hashes/Hashes.h ../RNG/RNG.h ../usehash.h
	$(CC) $(CFLAGS) DSA.cpp

ElGamal.o: ElGamal.h ElGamal.cpp ../common/integer.h ../RNG/RNG.h
	$(CC) $(CFLAGS) ElGamal.cpp

RSA.o: RSA.h RSA.cpp ../consts.h ../common/includes.h ../common/integer.h ../RNG/RNG.h ../usehash.h
	$(CC) $(CFLAGS) RSA.cpp

clean:
	rm -f *.o