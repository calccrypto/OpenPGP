# OpenPGP tests Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -Igoogletest/googletest/include
LDFLAGS=-lOpenPGP -lgmpxx -lgmp -lbz2 -lz -lgtest -lpthread -Lgoogletest/googlemock/gtest -L..
AR=ar
TARGET=tests

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs testcases run clean clean-all

libs:
	$(MAKE) -C ..

testcases:
	$(MAKE) -C testcases

$(TARGET): main.cc libs testcases
	$(CXX) $(CXXFLAGS) main.cc testcases/*.o $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

clean-all: clean
	$(MAKE) clean -C testcases
	$(MAKE) clean-all -C ..
