# OpenPGP executable modules Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -fPIC

include objects.mk

all: $(MODULES_OBJECTS)

gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: debug

.PHONY: clean

%.o : %.cpp %.h modules.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(MODULES_OBJECTS)

