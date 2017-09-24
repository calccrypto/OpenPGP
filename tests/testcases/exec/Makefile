# exec testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -fPIC -I../../../../googletest/googletest/include -I../../..

include objects.mk

all: $(EXEC_TESTCASES_OBJECTS) modules testmodules

debug: CXXFLAGS += -g
debug: all

gpg-debug: debug

.PHONY: modules testmodules clean

modules:
	$(MAKE) $(MAKECMDGOALS) -C ../../../exec/modules

testmodules:
	$(MAKE) $(MAKECMDGOALS) -C modules

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(EXEC_TESTCASES_OBJECTS)

clean-all: clean
	$(MAKE) clean -C modules

