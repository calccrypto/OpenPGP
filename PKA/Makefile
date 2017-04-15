# PKA Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(PKA_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE

debug: CXXFLAGS += -g -O0 --coverage
debug: all

.PHONY: clean

%.o : %.cpp %.h ../RNG/RNGs.h ../common/includes.h ../mpi.h ../pgptime.h PKA.h
	$(CXX) $(CXXFLAGS) $< -o $@

PKAs.o: PKAs.cpp PKAs.h $(PKA_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PKA_OBJECTS)
