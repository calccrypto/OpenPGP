# OpenPGP tests Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -pthread -Igtest-1.7.0/include
LDFLAGS=-lOpenPGP -lgmpxx -lgmp -lbz2 -lz -lgtest -lpthread -L. -L..
AR=ar
TARGET=tests

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs testcases gtest run clean clean-all

libs:
	$(MAKE) -C ..

testcases:
	$(MAKE) -C testcases

gtest:
	$(CXX) $(CXXFLAGS) -c -Igtest-1.7.0 gtest-1.7.0/src/gtest-all.cc -o gtest-all.o
	$(AR) -r libgtest.a gtest-all.o

$(TARGET): main.cc libs testcases gtest
	$(CXX) $(CXXFLAGS) main.cc testcases/*.o $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o *.a
	$(MAKE) clean -C testcases

clean-all: clean
	$(MAKE) clean -C ..
