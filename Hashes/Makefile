# Hashes Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(HASHES_OBJECTS)

.PHONY: clean

%.o : %.cpp %.h ../common/cryptomath.h ../common/includes.h 
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(HASHES_OBJECTS)
