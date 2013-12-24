# OpenPGP Makefile
CC=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: cfb.o decrypt.o encrypt.o generatekey.o mpi.o OpenPGP.o pgptime.o PKCS1.o radix64.o s2k.o sign.o signverify.o usehash.o verify.o common Encryptions Hashes Packets PKA RNG Subpackets

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
	$(CC) $(CFLAGS) cfb.cpp $(LFLAGS)

decrypt.o: decrypt.h decrypt.cpp PKA/ElGamal.h PKA/RSA.h cfb.h consts.h OpenPGP.h Packets/packets.h PKCS1.h s2k.h usehash.h
	$(CC) $(CFLAGS) decrypt.cpp $(LFLAGS)

encrypt.o: encrypt.h encrypt.cpp PKA/ElGamal.h PKA/RSA.h OpenPGP.h cfb.h PKCS1.h usehash.h
	$(CC) $(CFLAGS) encrypt.cpp $(LFLAGS)

generatekey.o: generatekey.h generatekey.cpp PKA/DSA.h PKA/ElGamal.h PKA/RSA.h OpenPGP.h cfb.h PKCS1.h signverify.h usehash.h
	$(CC) $(CFLAGS) generatekey.cpp $(LFLAGS)

mpi.o: mpi.h mpi.cpp common/includes.h
	$(CC) $(CFLAGS) mpi.cpp $(LFLAGS)

OpenPGP.o: OpenPGP.h OpenPGP.cpp common/includes.h consts.h Packets/packets.h pgptime.h Subpackets/subpackets.h radix64.h
	$(CC) $(CFLAGS) OpenPGP.cpp $(LFLAGS)

pgptime.o: pgptime.h pgptime.cpp consts.h
	$(CC) $(CFLAGS) pgptime.cpp $(LFLAGS)

PKCS1.o: PKCS1.h PKCS1.cpp consts.h common/includes.h RNG/RNG.h usehash.h
	$(CC) $(CFLAGS) PKCS1.cpp $(LFLAGS)

radix64.o: radix64.h radix64.cpp common/includes.h
	$(CC) $(CFLAGS) radix64.cpp $(LFLAGS)

s2k.o: s2k.h s2k.cpp common/includes.h consts.h usehash.h
	$(CC) $(CFLAGS) s2k.cpp $(LFLAGS)

sign.o: sign.h sign.cpp common/includes.h PKA/DSA.h PKA/RSA.h decrypt.h Packets/packets.h pgptime.h
	$(CC) $(CFLAGS) sign.cpp $(LFLAGS)

signverify.o: signverify.h signverify.cpp OpenPGP.h Packets/packets.h usehash.h
	$(CC) $(CFLAGS) signverify.cpp $(LFLAGS)

usehash.o: usehash.h usehash.cpp Hashes/Hashes.h
	$(CC) $(CFLAGS) usehash.cpp $(LFLAGS)

verify.o: verify.h verify.cpp PKA/DSA.h PKA/RSA.h OpenPGP.h signverify.h
	$(CC) $(CFLAGS) verify.cpp $(LFLAGS)

clean:
	rm -f *.o common/*.o Encryptions/*.o Hashes/*.o Packets/*.o PKA/*.o RNG/*.o Subpackets/*.o
