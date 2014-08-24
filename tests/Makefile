# OpenPGP tests Makefile
CXX?=g++
LFLAGS=-lOpenPGP -lgmpxx -lgmp -lbz2 -lz -lgtest -lpthread -L. -L..
CFLAGS=-std=c++11 -Wall -pthread -Igtest-1.7.0/include
AR=ar
TARGET=tests

debug: CFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs testcases gtest

libs:
	$(MAKE) -C ..

testcases:
	$(MAKE) -C testcases

gtest:
	$(CXX) $(CFLAGS) -c -Igtest-1.7.0 gtest-1.7.0/src/gtest-all.cc -o gtest-all.o
	$(AR) -r libgtest.a gtest-all.o

$(TARGET): main.cc libs testcases gtest
	$(CXX) $(CFLAGS) main.cc testcases/*.o $(LFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o *.a
	$(MAKE) -C .. clean
	$(MAKE) -C testcases clean
