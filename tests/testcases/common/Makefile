# common testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../googletest/googletest/include -I../../../common

debug: CXXFLAGS += -g
debug: all

.PHONY: integer

integer:
	$(MAKE) -C integer

all: $(COMMON_TESTCASES_OBJECTS) integer

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMMON_TESTCASES_OBJECTS)
