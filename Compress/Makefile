# Compression Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(COMPRESS_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE

debug: CXXFLAGS += -g -O0 --coverage
debug: all

.PHONY: clean

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Compress.o: Compress.cpp Compress.h $(COMPRESS_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMPRESS_OBJECTS)
