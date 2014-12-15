# OpenPGP Makefile
CXX?=g++
LDFLAGS=
CXXFLAGS=-std=c++11 -Wall -c
AR=ar
TARGET=libOpenPGP.a
INSTALL=/usr/local

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: common Compress Encryptions Hashes Packets PKA RNG Subpackets

common:
	$(MAKE) -C common

Compress:
	$(MAKE) -C Compress

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
	$(CXX) $(CXXFLAGS) cfb.cpp

decrypt.o: decrypt.h decrypt.cpp Compress/Compress.h Hashes/Hashes.h Packets/packets.h PKA/PKA.h cfb.h consts.h PGPKey.h PGPMessage.h PKCS1.h verify.h
	$(CXX) $(CXXFLAGS) decrypt.cpp

encrypt.o: encrypt.h encrypt.cpp Compress/Compress.h Hashes/Hashes.h PKA/PKA.h cfb.h PGPKey.h PGPMessage.h PKCS1.h revoke.h
	$(CXX) $(CXXFLAGS) encrypt.cpp

generatekey.o: generatekey.h generatekey.cpp Hashes/Hashes.h PKA/PKA.h cfb.h PGPKey.h pgptime.h PKCS1.h sign.h sigcalc.h
	$(CXX) $(CXXFLAGS) generatekey.cpp

mpi.o: mpi.h mpi.cpp common/includes.h
	$(CXX) $(CXXFLAGS) mpi.cpp

PGP.o: PGP.h PGP.cpp common/includes.h Packets/packets.h consts.h pgptime.h radix64.h
	$(CXX) $(CXXFLAGS) PGP.cpp

PGPCleartextSignature.o: PGPCleartextSignature.h PGPCleartextSignature.cpp PGP.h PGPDetachedSignature.h
	$(CXX) $(CXXFLAGS) PGPCleartextSignature.cpp

PGPDetachedSignature.o: PGPDetachedSignature.h PGPDetachedSignature.cpp PGP.h
	$(CXX) $(CXXFLAGS) PGPDetachedSignature.cpp

PGPKey.o: PGPKey.h PGPKey.cpp Packets/packets.h PGP.h
	$(CXX) $(CXXFLAGS) PGPKey.cpp

PGPMessage.o: PGPMessage.h PGPMessage.cpp PGP.h
	$(CXX) $(CXXFLAGS) PGPMessage.cpp

pgptime.o: pgptime.h pgptime.cpp consts.h
	$(CXX) $(CXXFLAGS) pgptime.cpp

PKCS1.o: PKCS1.h PKCS1.cpp common/includes.h RNG/RNG.h consts.h pgptime.h
	$(CXX) $(CXXFLAGS) PKCS1.cpp

radix64.o: radix64.h radix64.cpp common/includes.h
	$(CXX) $(CXXFLAGS) radix64.cpp

revoke.o: revoke.h revoke.cpp PGPKey.h PKCS1.h mpi.h PGPKey.h PKCS1.h sign.h verify.h
	$(CXX) $(CXXFLAGS) revoke.cpp

sigcalc.o: sigcalc.h sigcalc.cpp Hashes/Hashes.h Packets/packets.h pgptime.h
	$(CXX) $(CXXFLAGS) sigcalc.cpp

sign.o: sign.h sign.cpp common/includes.h Compress/Compress.h Packets/packets.h PKA/PKA.h decrypt.h mpi.h PGPCleartextSignature.h PGPDetachedSignature.h PGPKey.h PGPMessage.h pgptime.h revoke.h sigcalc.h
	$(CXX) $(CXXFLAGS) sign.cpp

verify.o: verify.h verify.cpp Packets/packets.h PKA/PKA.h mpi.h PGPCleartextSignature.h PGPDetachedSignature.h PGPMessage.h PGPKey.h PKCS1.h sigcalc.h
	$(CXX) $(CXXFLAGS) verify.cpp

$(TARGET): cfb.o decrypt.o encrypt.o generatekey.o mpi.o PGP.o PGPCleartextSignature.o PGPDetachedSignature.o PGPKey.o PGPMessage.o pgptime.o PKCS1.o radix64.o revoke.o sign.o sigcalc.o verify.o common Compress Encryptions Hashes Packets PKA RNG Subpackets
	$(AR) -r $(TARGET) cfb.o decrypt.o encrypt.o generatekey.o mpi.o PGP.o PGPCleartextSignature.o PGPDetachedSignature.o PGPKey.o PGPMessage.o pgptime.o PKCS1.o radix64.o revoke.o sign.o sigcalc.o verify.o common/*.o Compress/*.o Encryptions/*.o Hashes/*.o Packets/*.o PKA/*.o RNG/*.o Subpackets/*.o

#install:
#	cp $(TARGET) $(INSTALL)/lib

#uninstall:
#	rm $(INSTALL)/lib/$(TARGET)

clean:
	rm -f *.o $(TARGET)
	$(MAKE) -C common clean
	$(MAKE) -C Compress clean
	$(MAKE) -C Encryptions clean
	$(MAKE) -C Hashes clean
	$(MAKE) -C Packets clean
	$(MAKE) -C PKA clean
	$(MAKE) -C RNG clean
	$(MAKE) -C Subpackets clean
