# OpenPGP Makefile
CC=g++
LFLAGS=
BFLAGS=-std=c++11 -Wall
CFLAGS= $(BFLAGS) -c
TARGET=OpenPGP

debug: BFLAGS += -g
debug: all

all: $(TARGET)

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

$(TARGET): main.o cfb.o decrypt.o encrypt.o generatekey.o mpi.o OpenPGP.o packets.o pgptime.o PKCS1.o radix64.o s2k.o sign.o signverify.o usehash.o verify.o common Encryptions Hashes Packets PKA RNG Subpackets
	$(CC) $(BFLAGS) main.o cfb.o decrypt.o encrypt.o generatekey.o mpi.o OpenPGP.o packets.o pgptime.o PKCS1.o radix64.o s2k.o sign.o signverify.o usehash.o verify.o common/*.o Encryptions/*.o Hashes/*.o Packets/*.o PKA/*.o RNG/*.o Subpackets/*.o -o $(TARGET)

main.o: main.cpp  OpenPGP.h encrypt.h decrypt.h generatekey.h sign.h verify.h
	$(CC) $(CFLAGS) main.cpp

cfb.o: cfb.h cfb.cpp Encryptions/Encryptions.h RNG/RNG.h consts.h
	$(CC) $(CFLAGS) cfb.cpp

decrypt.o: decrypt.h decrypt.cpp PKA/ElGamal.h PKA/RSA.h cfb.h consts.h OpenPGP.h packets.h PKCS1.h s2k.h usehash.h
	$(CC) $(CFLAGS) decrypt.cpp

encrypt.o: encrypt.h encrypt.cpp PKA/ElGamal.h PKA/RSA.h OpenPGP.h cfb.h PKCS1.h usehash.h
	$(CC) $(CFLAGS) encrypt.cpp

generatekey.o: generatekey.h generatekey.cpp PKA/DSA.h PKA/ElGamal.h PKA/RSA.h OpenPGP.h cfb.h PKCS1.h signverify.h usehash.h
	$(CC) $(CFLAGS) generatekey.cpp

mpi.o: mpi.h mpi.cpp common/includes.h common/integer.h
	$(CC) $(CFLAGS) mpi.cpp

OpenPGP.o: OpenPGP.h OpenPGP.cpp common/includes.h consts.h packets.h pgptime.h subpackets.h radix64.h
	$(CC) $(CFLAGS) OpenPGP.cpp

packets.o: packets.h packets.cpp Packets/packet.h Packets/Tag0.h Packets/Tag1.h Packets/Tag2.h Packets/Tag3.h Packets/Tag4.h Packets/Tag5.h Packets/Tag6.h Packets/Tag7.h Packets/Tag8.h Packets/Tag9.h Packets/Tag10.h Packets/Tag11.h Packets/Tag12.h Packets/Tag13.h Packets/Tag14.h Packets/Tag17.h Packets/Tag18.h Packets/Tag19.h
	$(CC) $(CFLAGS) packets.cpp

pgptime.o: pgptime.h pgptime.cpp consts.h
	$(CC) $(CFLAGS) pgptime.cpp

PKCS1.o: PKCS1.h PKCS1.cpp consts.h common/includes.h RNG/RNG.h usehash.h
	$(CC) $(CFLAGS) PKCS1.cpp

radix64.o: radix64.h radix64.cpp common/includes.h
	$(CC) $(CFLAGS) radix64.cpp

s2k.o: s2k.h s2k.cpp common/includes.h consts.h usehash.h
	$(CC) $(CFLAGS) s2k.cpp

sign.o: sign.h sign.cpp common/includes.h PKA/DSA.h PKA/RSA.h decrypt.h packets.h pgptime.h
	$(CC) $(CFLAGS) sign.cpp

signverify.o: signverify.h signverify.cpp OpenPGP.h packets.h usehash.h
	$(CC) $(CFLAGS) signverify.cpp

usehash.o: usehash.h usehash.cpp Hashes/Hashes.h
	$(CC) $(CFLAGS) usehash.cpp

verify.o: verify.h verify.cpp PKA/DSA.h PKA/RSA.h OpenPGP.h signverify.h
	$(CC) $(CFLAGS) verify.cpp

clean:
	rm -f *.o common/*.o Encryptions/*.o Hashes/*.o Packets/*.o PKA/*.o RNG/*.o Subpackets/*.o $(TARGET)
