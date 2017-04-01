# Subpackets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(SUBPACKETS_OBJECTS)

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(SUBPACKETS_OBJECTS)

