# Subpackets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(TAG2_SUBPACKET_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(TAG2_SUBPACKET_OBJECTS)

