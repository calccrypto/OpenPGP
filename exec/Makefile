# OpenPGP executable Makefile
CXX?=g++
LFLAGS=-lOpenPGP -lgmpxx -lgmp -L..
CFLAGS=-std=c++11 -Wall
TARGET=OpenPGP

debug: CFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs

libs:
	$(MAKE) -C ..

$(TARGET): main.cpp libs
	$(CXX) $(CFLAGS) main.cpp $(LFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)
	$(MAKE) -C .. clean
