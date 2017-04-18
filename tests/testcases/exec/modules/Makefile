# Modules testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../../googletest/googletest/include -I../../../..

include objects.mk

all: $(MODULES_TESTCASES_OBJECTS)

debug: CXXFLAGS += -g
debug: all

gpg-debug: debug

.PHONY: clean

list.o: list.cpp ../../../../exec/modules/list.h
	$(CXX) $(CXXFLAGS) $< -o $@

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(MODULES_TESTCASES_OBJECTS)
