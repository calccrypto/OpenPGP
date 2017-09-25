# Modules testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../../googletest/googletest/include -I../../../..

include objects.mk

all: $(MODULES_TESTCASES_OBJECTS)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: clean

list.o: list.cpp ../../../../exec/modules/list.h
	$(CXX) $(CXXFLAGS) $< -o $@

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(MODULES_TESTCASES_OBJECTS)
