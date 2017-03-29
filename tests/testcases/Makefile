# OpenPGP testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../googletest/googletest/include -I../..

debug: CXXFLAGS += -g
debug: all

include objects.mk

.PHONY: common Compress Encryptions Hashes PKA

common:
	$(MAKE) -C common

Compress:
	$(MAKE) -C Compress

Encryptions:
	$(MAKE) -C Encryptions

Hashes:
	$(MAKE) -C Hashes

PKA:
	$(MAKE) -C PKA

all: $(TESTCASES_OBJECTS) common Compress Encryptions Hashes PKA

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
