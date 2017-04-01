# PKA Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(PKA_OBJECTS)

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(PKA_OBJECTS)
