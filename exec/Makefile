# OpenPGP commandline Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall
LDFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L..
TARGET=OpenPGP

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: lib clean clean-all

lib:
	$(MAKE) -C ..

$(TARGET): main.cpp ../OpenPGP.h lib
	$(CXX) $(CXXFLAGS) main.cpp $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

clean-all: clean
	$(MAKE) clean-all -C ..