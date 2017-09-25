# Encryptions Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(ENCRYPTIONS_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: clean

%.o : %.cpp %.h ../common/cryptomath.h ../common/includes.h SymAlg.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(ENCRYPTIONS_OBJECTS)
