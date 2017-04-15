# OpenPGP executable modules Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c

include objects.mk

all: $(MODULES_OBJECTS)

debug: CXXFLAGS += -g -O0 --coverage
debug: all

.PHONY: clean

%.o : %.cpp %.h modules.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(MODULES_OBJECTS)

