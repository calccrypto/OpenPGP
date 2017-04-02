# Packets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

.PHONY: clean

all: $(PACKETS_OBJECTS)

%.o : %.cpp %.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

packet.o: packet.cpp packet.h ../common/includes.h ../Hashes/Hashes.h ../mpi.h ../pgptime.h
	$(CXX) $(CXXFLAGS) $< -o $@

packets.o: packets.cpp packets.h $(PACKETS_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

s2k.o: s2k.cpp s2k.h ../common/includes.h ../Hashes/Hashes.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag2.o: Tag2.cpp Tag2.h ../Subpackets/Subpackets.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag3.o: Tag3.cpp Tag3.h ../cfb.h packet.h s2k.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag8.o: Tag8.cpp Tag8.h ../Compress/Compress.h ../PGPMessage.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag17.o: Tag17.cpp Tag17.h ../Subpackets/subpackets.h packet.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PACKETS_OBJECTS)

