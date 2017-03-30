# common testcases Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -c -I../../../../googletest/googletest/include -I../../../common

debug: CXXFLAGS += -g
debug: all

all: $(COMMON_TESTCASES_OBJECTS)

%.o : %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(COMMON_TESTCASES_OBJECTS)
