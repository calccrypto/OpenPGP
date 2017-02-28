# Hashes Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include sources.make
OBJECTS=$(HASHES_SOURCES:.cpp=.o)

debug: CXXFLAGS += -g
debug: all

all: $(OBJECTS)

.PHONY: clean

%.o : %.cpp %.h ../common/cryptomath.h ../common/includes.h 
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS)
