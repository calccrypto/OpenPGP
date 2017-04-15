# common Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(COMMON_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE

debug: CXXFLAGS += -g
debug: all

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMMON_OBJECTS)
