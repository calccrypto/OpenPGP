# OpenPGP tests Makefile
CC=g++
LFLAGS=-lgmpxx -lgmp -lpthread
CFLAGS=-std=c++11 -Wall -pthread -Igtest-1.7.0/include
AR=ar
TARGET=tests

debug: BFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs testcases gtest

libs:
	$(MAKE) -C ..

testcases:
	$(MAKE) -C testcases

gtest:
	$(CC) $(CFLAGS) -c -Igtest-1.7.0 gtest-1.7.0/src/gtest-all.cc $(LFLAGS) -o gtest-all.o
	$(AR) -r libgtest.a gtest-all.o

$(TARGET): main.cpp libs testcases gtest
	$(CC) $(CFLAGS) main.cpp ../*.o ../*/*.o testcases/*.o $(LFLAGS) -L. -lgtest -o $(TARGET)

clean:
	rm -f $(TARGET) *.o *.a
	$(MAKE) -C .. clean
	$(MAKE) -C testcases clean
