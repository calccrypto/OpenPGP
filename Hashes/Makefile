# Hashes Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(HASHES_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE

debug: CXXFLAGS += -g -O0 --coverage
debug: all

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Hashes.o : Hashes.cpp Hashes.h  $(HASHES_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(HASHES_OBJECTS)
