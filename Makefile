# OpenPGP Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -fPIC
AR=ar
TARGET=libOpenPGP.a

include objects.mk
include common/objects.mk
include Compress/objects.mk
include Encryptions/objects.mk
include Hashes/objects.mk
include Misc/objects.mk
include Packets/objects.mk
include PKA/objects.mk
include RNG/objects.mk
include Subpackets/objects.mk

all: $(TARGET)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: common Compress Encryptions Hashes Misc Packets PKA RNG Subpackets clean clean-all

common:
	$(MAKE) $(MAKECMDGOALS) -C common

Compress:
	$(MAKE) $(MAKECMDGOALS) -C Compress

Encryptions:
	$(MAKE) $(MAKECMDGOALS) -C Encryptions

Hashes:
	$(MAKE) $(MAKECMDGOALS) -C Hashes

Misc:
	$(MAKE) $(MAKECMDGOALS) -C Misc

Packets:
	$(MAKE) $(MAKECMDGOALS) -C Packets

PKA:
	$(MAKE) $(MAKECMDGOALS) -C PKA

RNG:
	$(MAKE) $(MAKECMDGOALS) -C RNG

Subpackets:
	$(MAKE) $(MAKECMDGOALS) -C Subpackets

decrypt.o: decrypt.cpp decrypt.h Compress/Compress.h Encryptions/Encryptions.h Hashes/Hashes.h Misc/PKCS1.h Misc/cfb.h Misc/mpi.h PGPKey.h PGPMessage.h PKA/PKA.h Packets/packets.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

encrypt.o: encrypt.cpp encrypt.h Compress/Compress.h Encryptions/Encryptions.h Hashes/Hashes.h Misc/PKCS1.h Misc/cfb.h PGPKey.h PGPMessage.h PKA/PKA.h revoke.h sign.h
	$(CXX) $(CXXFLAGS) $< -o $@

generatekey.o: generatekey.cpp generatekey.h Encryptions/Encryptions.h Hashes/Hashes.h PGPKey.h PKA/PKA.h Misc/PKCS1.h Misc/cfb.h Misc/mpi.h Misc/pgptime.h Misc/sigcalc.h sign.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGP.o: PGP.cpp PGP.h common/includes.h Misc/radix64.h Packets/packets.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPCleartextSignature.o: PGPCleartextSignature.cpp PGPCleartextSignature.h Misc/sigcalc.h PGP.h PGPDetachedSignature.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPDetachedSignature.o: PGPDetachedSignature.cpp PGPDetachedSignature.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPKey.o: PGPKey.cpp PGPKey.h Packets/packets.h PKA/PKAs.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPMessage.o: PGPMessage.cpp PGPMessage.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

PGPRevocationCertificate.o: PGPRevocationCertificate.cpp PGPRevocationCertificate.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

revoke.o: revoke.cpp revoke.h Misc/mpi.h Misc/PKCS1.h PGPKey.h PGPRevocationCertificate.h sign.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

sign.o: sign.cpp sign.h Compress/Compress.h Hashes/Hashes.h PGPCleartextSignature.h PGPDetachedSignature.h PGPKey.h PGPMessage.h PKA/PKA.h Packets/packets.h common/includes.h decrypt.h Misc/mpi.h Misc/pgptime.h revoke.h Misc/sigcalc.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

verify.o: verify.cpp verify.h Misc/PKCS1.h Misc/mpi.h Misc/sigcalc.h PGPCleartextSignature.h PGPDetachedSignature.h PGPKey.h PGPMessage.h PGPRevocationCertificate.h PKA/PKA.h Packets/packets.h
	$(CXX) $(CXXFLAGS) $< -o $@

$(TARGET): $(OPENPGP_OBJECTS) common Compress Encryptions Hashes Misc Packets PKA RNG Subpackets
	$(AR) -r $(TARGET) $(OPENPGP_OBJECTS) $(addprefix common/, $(COMMON_OBJECTS)) $(addprefix Compress/, $(COMPRESS_OBJECTS)) $(addprefix Encryptions/, $(ENCRYPTIONS_OBJECTS)) $(addprefix Hashes/, $(HASHES_OBJECTS)) $(addprefix Misc/, $(MISC_OBJECTS))  $(addprefix Packets/, $(PACKETS_OBJECTS)) $(addprefix PKA/, $(PKA_OBJECTS)) $(addprefix RNG/, $(RNG_OBJECTS)) $(addprefix Subpackets/, $(SUBPACKETS_OBJECTS))

clean:
	rm -f $(TARGET)

clean-all: clean
	rm -f $(OPENPGP_OBJECTS)
	$(MAKE) clean -C common
	$(MAKE) clean -C Compress
	$(MAKE) clean -C Encryptions
	$(MAKE) clean -C Hashes
	$(MAKE) clean -C Misc
	$(MAKE) clean -C Packets
	$(MAKE) clean -C PKA
	$(MAKE) clean -C RNG
	$(MAKE) clean -C Subpackets