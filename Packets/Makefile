# Packets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(PACKETS_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: clean

%.o : %.cpp %.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

packet.o: packet.cpp packet.h ../Hashes/Hashes.h ../Misc/mpi.h ../Misc/pgptime.h ../common/includes.h
	$(CXX) $(CXXFLAGS) $< -o $@

packets.o: packets.cpp packets.h $(PACKETS_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

s2k.o: s2k.cpp s2k.h ../common/includes.h ../Hashes/Hashes.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag2.o: Tag2.cpp Tag2.h ../Hashes/Hashes.h ../PKA/PKAs.h ../Subpackets/Tag2Subpackets.h packet.h sigtypes.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag3.o: Tag3.cpp Tag3.h ../Misc/cfb.h packet.h s2k.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag8.o: Tag8.cpp Tag8.h ../Compress/Compress.h ../PGPMessage.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag17.o: Tag17.cpp Tag17.h ../Subpackets/Subpackets.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PACKETS_OBJECTS)

