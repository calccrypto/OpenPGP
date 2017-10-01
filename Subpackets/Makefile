# Subpackets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(SUBPACKET_OBJECTS) Tag2 Tag17

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: Tag2 Tag17 clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag2:
	$(MAKE) $(MAKECMDGOALS) -C Tag2

Tag17:
	$(MAKE) $(MAKECMDGOALS) -C Tag17

Subpacket.o: Subpacket.h Subpacket.cpp ../common/includes.h
	$(CXX) $(CXXFLAGS) Subpacket.cpp

clean:
	rm -f $(SUBPACKET_OBJECTS)
	$(MAKE) clean -C Tag2
	$(MAKE) clean -C Tag17
