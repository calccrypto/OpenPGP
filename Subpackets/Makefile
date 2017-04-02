# Subpackets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

.PHONY: Tag2Sub Tag17Sub clean

all: $(SUBPACKET_OBJECTS) Tag2Sub Tag17Sub

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Tag2Sub:
	$(MAKE) -f Tag2SubMakefile

Tag17Sub:
	$(MAKE) -f Tag17SubMakefile

Subpacket.o: Subpacket.h Subpacket.cpp ../common/includes.h
	$(CXX) $(CXXFLAGS) Subpacket.cpp

clean:
	rm -f $(SUBPACKETS_OBJECTS)

