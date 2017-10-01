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

%.o : %.cpp %.h Packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

Packet.o: Packet.cpp Packet.h ../Hashes/Hashes.h ../Misc/mpi.h ../Misc/pgptime.h ../common/includes.h
	$(CXX) $(CXXFLAGS) $< -o $@

Packets.o: Packets.cpp Packets.h $(PACKETS_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

Tag2.o: Tag2.cpp Tag2.h ../Hashes/Hashes.h ../Misc/sigtypes.h ../PKA/PKAs.h ../Subpackets/Tag2/Subpackets.h Packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag3.o: Tag3.cpp Tag3.h ../Misc/cfb.h Packet.h ../Misc/s2k.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag5.o: Tag5.cpp Tag5.h ../Misc/cfb.h ../Misc/mpi.h ../Misc/s2k.h Tag6.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag6.o: Tag6.cpp Tag6.h Key.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag8.o: Tag8.cpp Tag8.h ../Compress/Compress.h ../Message.h Packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag17.o: Tag17.cpp Tag17.h ../Subpackets/Tag17/Subpacket.h Packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PACKETS_OBJECTS)

