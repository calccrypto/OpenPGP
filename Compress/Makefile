# Compression Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(COMPRESS_OBJECTS)

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMPRESS_OBJECTS)
