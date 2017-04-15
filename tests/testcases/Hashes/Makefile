# Hashes testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../googletest/googletest/include -I../../..

include objects.mk

all: $(HASHES_TESTCASES_OBJECTS)

debug: CXXFLAGS += -g
debug: all

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(HASHES_TESTCASES_OBJECTS)
