# Subpackets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(SUBPACKET_OBJECTS) Tag2Sub Tag17Sub

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE

debug: CXXFLAGS += -g
debug: all

.PHONY: Tag2Sub Tag17Sub clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag2Sub:
	$(MAKE) $(MAKECMDGOALS) -f Tag2SubMakefile

Tag17Sub:
	$(MAKE) $(MAKECMDGOALS) -f Tag17SubMakefile

Subpacket.o: Subpacket.h Subpacket.cpp ../common/includes.h
	$(CXX) $(CXXFLAGS) Subpacket.cpp

clean:
	rm -f $(SUBPACKETS_OBJECTS)

