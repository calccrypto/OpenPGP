# OpenPGP Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c
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
include Subpackets/Tag2/objects.mk
include Subpackets/Tag17/objects.mk

all: $(TARGET)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: common Compress Encryptions Hashes Misc Packets PKA RNG Subpackets clean clean-all

# Subdirectories
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

# Top-level Types
PGP.o: PGP.cpp PGP.h common/includes.h Misc/radix64.h Packets/packets.h
	$(CXX) $(CXXFLAGS) $< -o $@

CleartextSignature.o: CleartextSignature.cpp CleartextSignature.h Misc/sigcalc.h PGP.h DetachedSignature.h
	$(CXX) $(CXXFLAGS) $< -o $@

DetachedSignature.o: DetachedSignature.cpp DetachedSignature.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

Key.o: Key.cpp Key.h Packets/packets.h PKA/PKAs.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

Message.o: Message.cpp Message.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

RevocationCertificate.o: RevocationCertificate.cpp RevocationCertificate.h PGP.h
	$(CXX) $(CXXFLAGS) $< -o $@

# Utility Functions
decrypt.o: decrypt.cpp decrypt.h Compress/Compress.h Encryptions/Encryptions.h Hashes/Hashes.h Misc/PKCS1.h Misc/cfb.h Misc/mpi.h Key.h Message.h PKA/PKA.h Packets/packets.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

encrypt.o: encrypt.cpp encrypt.h Compress/Compress.h Encryptions/Encryptions.h Hashes/Hashes.h Misc/PKCS1.h Misc/cfb.h Key.h Message.h PKA/PKA.h revoke.h sign.h
	$(CXX) $(CXXFLAGS) $< -o $@

keygen.o: keygen.cpp keygen.h Encryptions/Encryptions.h Hashes/Hashes.h Key.h PKA/PKA.h Misc/PKCS1.h Misc/cfb.h Misc/mpi.h Misc/pgptime.h Misc/sigcalc.h sign.h
	$(CXX) $(CXXFLAGS) $< -o $@

revoke.o: revoke.cpp revoke.h Misc/mpi.h Misc/PKCS1.h Key.h RevocationCertificate.h sign.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

sign.o: sign.cpp sign.h Compress/Compress.h Hashes/Hashes.h CleartextSignature.h DetachedSignature.h Key.h Message.h PKA/PKA.h Packets/packets.h common/includes.h decrypt.h Misc/mpi.h Misc/pgptime.h revoke.h Misc/sigcalc.h verify.h
	$(CXX) $(CXXFLAGS) $< -o $@

verify.o: verify.cpp verify.h Misc/PKCS1.h Misc/mpi.h Misc/sigcalc.h CleartextSignature.h DetachedSignature.h Key.h Message.h RevocationCertificate.h PKA/PKA.h Packets/packets.h
	$(CXX) $(CXXFLAGS) $< -o $@

# Library
$(TARGET): $(OPENPGP_OBJECTS) common Compress Encryptions Hashes Misc Packets PKA RNG Subpackets
	$(AR) -r $(TARGET) $(OPENPGP_OBJECTS) $(addprefix common/, $(COMMON_OBJECTS)) $(addprefix Compress/, $(COMPRESS_OBJECTS)) $(addprefix Encryptions/, $(ENCRYPTIONS_OBJECTS)) $(addprefix Hashes/, $(HASHES_OBJECTS)) $(addprefix Misc/, $(MISC_OBJECTS)) $(addprefix Packets/, $(PACKETS_OBJECTS)) $(addprefix PKA/, $(PKA_OBJECTS)) $(addprefix RNG/, $(RNG_OBJECTS)) $(addprefix Subpackets/, $(SUBPACKET_OBJECTS)) $(addprefix Subpackets/Tag2/, $(TAG2_SUBPACKET_OBJECTS)) $(addprefix Subpackets/Tag17/, $(TAG17_SUBPACKET_OBJECTS))

clean:
	rm -f $(TARGET)
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
