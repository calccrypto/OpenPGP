# OpenPGP Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c
AR=ar
TARGET=libOpenPGP.a

include sources.make
OPENPGP_OBJECTS=$(OPENPGP_SOURCES:.cpp=.o)

include common/sources.make
COMMON_OBJECTS=$(addprefix common/, $(COMMON_SOURCES:.cpp=.o))

include Compress/sources.make
COMPRESS_OBJECTS=$(addprefix Compress/, $(COMPRESS_SOURCES:.cpp=.o))

include Encryptions/sources.make
ENCRYPTIONS_OBJECTS=$(addprefix Encryptions/, $(ENCRYPTIONS_SOURCES:.cpp=.o))

include Hashes/sources.make
HASHES_OBJECTS=$(addprefix Hashes/, $(HASHES_SOURCES:.cpp=.o))

include Packets/sources.make
PACKETS_OBJECTS=$(addprefix Packets/, $(PACKETS_SOURCES:.cpp=.o))

include PKA/sources.make
PKA_OBJECTS=$(addprefix PKA/, $(PKA_SOURCES:.cpp=.o))

include RNG/sources.make
RNG_OBJECTS=$(addprefix RNG/, $(RNG_SOURCES:.cpp=.o))

include Subpackets/sources.make
SUBPACKETS_OBJECTS=$(addprefix Subpackets/, $(SUBPACKETS_SOURCES:.cpp=.o))

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: common Compress Encryptions Hashes Packets PKA RNG Subpackets clean

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

$(TARGET): $(OPENPGP_OBJECTS) common Compress Encryptions Hashes Packets PKA RNG Subpackets
	$(AR) -r $(TARGET) $(OPENPGP_OBJECTS) $(COMMON_OBJECTS) $(COMPRESS_OBJECTS) $(ENCRYPTIONS_OBJECTS) $(HASHES_OBJECTS) $(PACKETS_OBJECTS) $(PKA_OBJECTS) $(RNG_OBJECTS) $(SUBPACKETS_OBJECTS)

clean:
	rm -f $(OPENPGP_OBJECTS) $(TARGET)

clean-all: clean
	$(MAKE) clean -C common
	$(MAKE) clean -C Compress
	$(MAKE) clean -C Encryptions
	$(MAKE) clean -C Hashes
	$(MAKE) clean -C Packets
	$(MAKE) clean -C PKA
	$(MAKE) clean -C RNG
	$(MAKE) clean -C Subpackets
