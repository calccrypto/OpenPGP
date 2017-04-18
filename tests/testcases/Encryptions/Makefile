# Encryptions testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../googletest/googletest/include -I../../..

include objects.mk

all: $(ENCRYPTIONS_TESTCASES_OBJECTS)

debug: CXXFLAGS += -g
debug: all

gpg-debug: debug

.PHONY: clean

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(ENCRYPTIONS_TESTCASES_OBJECTS)
