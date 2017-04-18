# common testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../googletest/googletest/include -I../../../common

all: $(COMMON_TESTCASES_OBJECTS)

debug: CXXFLAGS += -g
debug: all

gpg-debug: debug

.PHONY: clean

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMMON_TESTCASES_OBJECTS)
