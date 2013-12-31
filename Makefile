# OpenPGP Makefile
CC=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: cfb.o decrypt.o encrypt.o generatekey.o mpi.o pgptime.o PKCS1.o radix64.o revoke.o sign.o sigcalc.o usehash.o verify.o common Encryptions Hashes Keys Packets PKA RNG Subpackets

.PHONY: common Encryptions Hashes Keys Packets PKA RNG Subpackets

common:
	$(MAKE) -C common

Encryptions:
	$(MAKE) -C Encryptions

Hashes:
	$(MAKE) -C Hashes

Keys:
	$(MAKE) -C Keys

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

decrypt.o: decrypt.h decrypt.cpp Keys/PGPTypes.h PKA/PKA.h cfb.h consts.h Packets/packets.h PKCS1.h usehash.h
	$(CC) $(CFLAGS) $(LFLAGS) decrypt.cpp

encrypt.o: encrypt.h encrypt.cpp Keys/PGPTypes.h PKA/PKA.h cfb.h PKCS1.h usehash.h
	$(CC) $(CFLAGS) $(LFLAGS) encrypt.cpp

generatekey.o: generatekey.h generatekey.cpp Keys/PGPTypes.h PKA/PKA.h cfb.h PKCS1.h sigcalc.h usehash.h
	$(CC) $(CFLAGS) $(LFLAGS) generatekey.cpp

mpi.o: mpi.h mpi.cpp common/includes.h
	$(CC) $(CFLAGS) $(LFLAGS) mpi.cpp

pgptime.o: pgptime.h pgptime.cpp consts.h
	$(CC) $(CFLAGS) pgptime.cpp

PKCS1.o: PKCS1.h PKCS1.cpp common/includes.h RNG/RNG.h consts.h pgptime.h usehash.h
	$(CC) $(CFLAGS) $(LFLAGS) PKCS1.cpp

radix64.o: radix64.h radix64.cpp common/includes.h
	$(CC) $(CFLAGS) radix64.cpp

revoke.o: revoke.h revoke.cpp Keys/PGPTypes.h PKCS1.h sign.h
	$(CC) $(CFLAGS) $(LFLAGS) revoke.cpp

sign.o: sign.h sign.cpp common/includes.h Keys/PGPTypes.h Packets/packets.h PKA/PKA.h decrypt.h pgptime.h sigcalc.h
	$(CC) $(CFLAGS) $(LFLAGS) sign.cpp

sigcalc.o: sigcalc.h sigcalc.cpp Keys/PGPTypes.h Packets/packets.h pgptime.h usehash.h
	$(CC) $(CFLAGS) sigcalc.cpp

usehash.o: usehash.h usehash.cpp Hashes/Hashes.h
	$(CC) $(CFLAGS) usehash.cpp

verify.o: verify.h verify.cpp Keys/PGPTypes.h PKA/PKA.h sigcalc.h
	$(CC) $(CFLAGS) $(LFLAGS) verify.cpp

clean:
	rm -f *.o common/*.o Encryptions/*.o Hashes/*.o Keys/*.o Packets/*.o PKA/*.o RNG/*.o Subpackets/*.o
