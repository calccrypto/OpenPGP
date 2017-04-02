# Hashes Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

.PHONY: clean

all: $(HASHES_OBJECTS)

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Hashes.o : Hashes.cpp Hashes.h  $(HASHES_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(HASHES_OBJECTS)
