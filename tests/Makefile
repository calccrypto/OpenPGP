# OpenPGP tests Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -I../../googletest/googletest/include
LDFLAGS=-lOpenPGP -lgmpxx -lgmp -lbz2 -lz -lgtest -lpthread -L../../googletest/googlemock/gtest -L..
AR=ar
TARGET=tests

include testcases/objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs testcases run clean clean-all

libs:
	$(MAKE) -C ..

testcases:
	$(MAKE) -C testcases

$(TARGET): main.cc libs testcases
	$(CXX) $(CXXFLAGS) main.cc $(addprefix testcases/, $(TESTCASES_OBJECTS)) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

clean-all: clean
	$(MAKE) clean -C testcases
	$(MAKE) clean-all -C ..