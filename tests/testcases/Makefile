# OpenPGP testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../googletest/googletest/include -I../..

include objects.mk

all: $(TESTCASES_OBJECTS) common Compress Encryptions Hashes PKA

debug: CXXFLAGS += -g -O0 --coverage
debug: all

.PHONY: common Compress Encryptions Hashes PKA

common:
	$(MAKE) $(MAKECMDGOALS) -C common

Compress:
	$(MAKE) $(MAKECMDGOALS) -C Compress

Encryptions:
	$(MAKE) $(MAKECMDGOALS) -C Encryptions

Hashes:
	$(MAKE) $(MAKECMDGOALS) -C Hashes

PKA:
	$(MAKE) $(MAKECMDGOALS) -C PKA

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(TESTCASES_OBJECTS)

clean-all: clean
	$(MAKE) clean -C common
	$(MAKE) clean -C Compress
	$(MAKE) clean -C Encryptions
	$(MAKE) clean -C Hashes
	$(MAKE) clean -C PKA
