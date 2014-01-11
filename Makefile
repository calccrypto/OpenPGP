# OpenPGP Makefile
CC=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: cfb.o decrypt.o encrypt.o generatekey.o mpi.o PGP.o PGPSignedMessage.o pgptime.o PKCS1.o radix64.o revoke.o sign.o sigcalc.o verify.o common Encryptions Hashes Packets PKA RNG Subpackets

.PHONY: common Encryptions Hashes Packets PKA RNG Subpackets

common:
	$(MAKE) -C common

Encryptions:
	$(MAKE) -C Encryptions

Hashes:
	$(MAKE) -C Hashes

Packets:
	$(MAKE) -C Packets

PKA:
	$(MAKE) -C PKA

RNG:
	$(MAKE) -C RNG

Subpackets:
	$(MAKE) -C Subpackets

cfb.o: cfb.h cfb.cpp Encryptions/Encryptions.h RNG/RNG.h consts.h
	$(CC) $(CFLAGS) cfb.cpp

decrypt.o: decrypt.h decrypt.cpp Hashes/Hashes.h Packets/packets.h PKA/PKA.h cfb.h consts.h PGP.h PKCS1.h
	$(CC) $(CFLAGS) $(LFLAGS) decrypt.cpp

encrypt.o: encrypt.h encrypt.cpp Hashes/Hashes.h PKA/PKA.h cfb.h PGP.h PKCS1.h
	$(CC) $(CFLAGS) $(LFLAGS) encrypt.cpp

generatekey.o: generatekey.h generatekey.cpp Hashes/Hashes.h PKA/PKA.h cfb.h PGP.h pgptime.h PKCS1.h sign.h sigcalc.h
	$(CC) $(CFLAGS) $(LFLAGS) generatekey.cpp

mpi.o: mpi.h mpi.cpp common/includes.h
	$(CC) $(CFLAGS) $(LFLAGS) mpi.cpp

PGP.o: PGP.h PGP.cpp common/includes.h Packets/packets.h Subpackets/subpackets.h consts.h pgptime.h radix64.h
	$(CC) $(CFLAGS) PGP.cpp

PGPSignedMessage.o: PGPSignedMessage.h PGPSignedMessage.cpp PGP.h
	$(CC) $(CFLAGS) PGPSignedMessage.cpp

pgptime.o: pgptime.h pgptime.cpp consts.h
	$(CC) $(CFLAGS) pgptime.cpp

PKCS1.o: PKCS1.h PKCS1.cpp common/includes.h RNG/RNG.h consts.h pgptime.h
	$(CC) $(CFLAGS) $(LFLAGS) PKCS1.cpp

radix64.o: radix64.h radix64.cpp common/includes.h
	$(CC) $(CFLAGS) radix64.cpp

revoke.o: revoke.h revoke.cpp PGP.h PKCS1.h sign.h verify.h
	$(CC) $(CFLAGS) $(LFLAGS) revoke.cpp

sigcalc.o: sigcalc.h sigcalc.cpp Hashes/Hashes.h Packets/packets.h PGP.h pgptime.h
	$(CC) $(CFLAGS) sigcalc.cpp

sign.o: sign.h sign.cpp common/includes.h Packets/packets.h PKA/PKA.h decrypt.h PGP.h PGPSignedMessage.h pgptime.h sigcalc.h
	$(CC) $(CFLAGS) $(LFLAGS) sign.cpp

verify.o: verify.h verify.cpp Packets/packets.h PKA/PKA.h PGP.h PGPSignedMessage.h sigcalc.h
	$(CC) $(CFLAGS) $(LFLAGS) verify.cpp

clean:
	rm -f *.o
	$(MAKE) -C common clean
	$(MAKE) -C Encryptions clean
	$(MAKE) -C Hashes clean
	$(MAKE) -C Packets clean
	$(MAKE) -C PKA clean
	$(MAKE) -C RNG clean
	$(MAKE) -C Subpackets clean
