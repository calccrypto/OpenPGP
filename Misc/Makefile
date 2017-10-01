# Misc Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(MISC_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: clean

%.o : %.cpp %.h Packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

cfb.o: cfb.cpp cfb.h ../Encryptions/Encryptions.h ../Packets/Packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

mpi.o: mpi.cpp mpi.h ../common/includes.h
	$(CXX) $(CXXFLAGS) $< -o $@

pgptime.o: pgptime.cpp pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

PKCS1.o: PKCS1.cpp PKCS1.h ../common/includes.h ../Hashes/Hashes.h ../RNG/RNGs.h mpi.h pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

radix64.o: radix64.cpp radix64.h ../common/includes.h
	$(CXX) $(CXXFLAGS) $< -o $@

s2k.o: s2k.cpp s2k.h ../common/includes.h ../Hashes/Hashes.h
	$(CXX) $(CXXFLAGS) $< -o $@

sigcalc.o: sigcalc.cpp sigcalc.h ../Hashes/Hashes.h ../Packets/packets.h pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(MISC_OBJECTS)
