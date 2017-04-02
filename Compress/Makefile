# Compression Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -DGPG_COMPATIBLE

include objects.mk

debug: CXXFLAGS += -g
debug: all

.PHONY: clean

all: $(COMPRESS_OBJECTS)

%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $< -o $@

Compress.o: Compress.cpp Compress.h $(COMPRESS_OBJECTS:.o=.h)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMPRESS_OBJECTS)
