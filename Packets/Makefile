# Packets Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(PACKETS_OBJECTS)

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PACKETS_OBJECTS)

