# OpenPGP Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE
AR=ar
TARGET=libOpenPGP.a

include objects.mk
include common/objects.mk
include Compress/objects.mk
include Encryptions/objects.mk
include Hashes/objects.mk
include Packets/objects.mk
include PKA/objects.mk
include RNG/objects.mk
include Subpackets/objects.mk

debug: CXXFLAGS += -g
debug: all

.PHONY: common Compress Encryptions Hashes Packets PKA RNG Subpackets clean clean-all

all: $(TARGET)

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

cfb.o: cfb.cpp cfb.h Encryptions/Encryptions.h Packets/packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

decrypt.o: decrypt.cpp decrypt.h Compress/Compress.h Encryptions/Encryptions.h Hashes/Hashes.h PGPKey.h PGPMessage.h PKA/PKA.h PKCS1.h Packets/packets.h cfb.h mpi.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

encrypt.o: encrypt.cpp encrypt.h Compress/Compress.h Encryptions/Encryptions.h Hashes/Hashes.h PGPKey.h PGPMessage.h PKA/PKA.h PKCS1.h cfb.h revoke.h sign.h
	$(CXX) $(CXXFLAGS) $< -o $@

generatekey.o: generatekey.cpp generatekey.h Encryptions/Encryptions.h Hashes/Hashes.h PGPKey.h PKA/PKA.h PKCS1.h cfb.h mpi.h pgptime.h sigcalc.h sign.h
	$(CXX) $(CXXFLAGS) $< -o $@

mpi.o: mpi.cpp mpi.h common/includes.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGP.o: PGP.cpp PGP.h common/includes.h Packets/packets.h pgptime.h radix64.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPCleartextSignature.o: PGPCleartextSignature.cpp PGPCleartextSignature.h PGP.h PGPDetachedSignature.h sigcalc.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPDetachedSignature.o: PGPDetachedSignature.cpp PGPDetachedSignature.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPKey.o: PGPKey.cpp PGPKey.h Packets/packets.h PKA/PKAs.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPMessage.o: PGPMessage.cpp PGPMessage.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPRevocationCertificate.o: PGPRevocationCertificate.cpp PGPRevocationCertificate.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

pgptime.o: pgptime.cpp pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

PKCS1.o: PKCS1.cpp PKCS1.h common/includes.h Hashes/Hashes.h RNG/RNGs.h mpi.h pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

radix64.o: radix64.cpp radix64.h common/includes.h
	$(CXX) $(CXXFLAGS) $< -o $@

revoke.o: revoke.cpp revoke.h PGPKey.h PGPRevocationCertificate.h PKCS1.h mpi.h sign.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

sigcalc.o: sigcalc.cpp sigcalc.h Hashes/Hashes.h Packets/packets.h pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

sign.o: sign.cpp sign.h Compress/Compress.h Hashes/Hashes.h PGPCleartextSignature.h PGPDetachedSignature.h PGPKey.h PGPMessage.h PKA/PKA.h Packets/packets.h common/includes.h decrypt.h mpi.h pgptime.h revoke.h sigcalc.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

verify.o: verify.cpp verify.h PGPCleartextSignature.h PGPDetachedSignature.h PGPKey.h PGPMessage.h PGPRevocationCertificate.h PKA/PKA.h PKCS1.h Packets/packets.h mpi.h sigcalc.h
	$(CXX) $(CXXFLAGS) $< -o $@

$(TARGET): $(OPENPGP_OBJECTS) common Compress Encryptions Hashes Packets PKA RNG Subpackets
	$(AR) -r $(TARGET) $(OPENPGP_OBJECTS) $(addprefix common/, $(COMMON_OBJECTS)) $(addprefix Compress/, $(COMPRESS_OBJECTS)) $(addprefix Encryptions/, $(ENCRYPTIONS_OBJECTS)) $(addprefix Hashes/, $(HASHES_OBJECTS)) $(addprefix Packets/, $(PACKETS_OBJECTS)) $(addprefix PKA/, $(PKA_OBJECTS)) $(addprefix RNG/, $(RNG_OBJECTS)) $(addprefix Subpackets/, $(SUBPACKETS_OBJECTS))

clean:
	rm -f $(TARGET)

clean-all: clean
	rm -f $(OPENPGP_OBJECTS)
	$(MAKE) clean -C common
	$(MAKE) clean -C Compress
	$(MAKE) clean -C Encryptions
	$(MAKE) clean -C Hashes
	$(MAKE) clean -C Packets
	$(MAKE) clean -C PKA
	$(MAKE) clean -C RNG
	$(MAKE) clean -C Subpackets