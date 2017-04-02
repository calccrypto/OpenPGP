# PKA Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

.PHONY: clean

all: $(PKA_OBJECTS)

%.o : %.cpp %.h ../RNG/RNGs.h ../common/includes.h ../mpi.h ../pgptime.h PKA.h
	$(CXX) $(CXXFLAGS) $< -o $@

PKAs.o: PKAs.cpp PKAs.h $(PKA_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PKA_OBJECTS)
