# OpenPGP testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../googletest/googletest/include -I../..

include objects.mk

all: $(TESTCASES_OBJECTS) common Compress Encryptions exec Hashes Misc PKA

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: common Compress Encryptions exec Hashes Misc PKA clean clean-all

common:
	$(MAKE) $(MAKECMDGOALS) -C common

Compress:
	$(MAKE) $(MAKECMDGOALS) -C Compress

Encryptions:
	$(MAKE) $(MAKECMDGOALS) -C Encryptions

exec:
	$(MAKE) $(MAKECMDGOALS) -C exec

Hashes:
	$(MAKE) $(MAKECMDGOALS) -C Hashes

Misc:
	$(MAKE) $(MAKECMDGOALS) -C Misc

PKA:
	$(MAKE) $(MAKECMDGOALS) -C PKA

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(TESTCASES_OBJECTS)
	$(MAKE) clean -C common
	$(MAKE) clean -C Compress
	$(MAKE) clean -C Encryptions
	$(MAKE) clean -C exec
	$(MAKE) clean -C Hashes
	$(MAKE) clean -C Misc
	$(MAKE) clean -C PKA
