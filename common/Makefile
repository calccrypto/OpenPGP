# common Makefile
CXX?=g++
LDFLAGS=
CXXFLAGS=-std=c++11 -Wall -c

debug: CXXFLAGS += -g
debug: all

all: includes.o integer.o

includes.o: includes.h includes.cpp
	$(CXX) $(CXXFLAGS) includes.cpp

integer.o: integer.h integer.cpp
	$(CXX) $(CXXFLAGS) integer.cpp

clean:
	rm -f *.o
