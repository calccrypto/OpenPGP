# Hashes testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../googletest/googletest/include -I../../..

include objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(HASHES_TESTCASES_OBJECTS)

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(HASHES_TESTCASES_OBJECTS)
