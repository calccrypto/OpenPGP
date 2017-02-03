# OpenPGP commandline Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall
LDFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L..
TARGET=OpenPGP

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs clean clean-all

libs:
	$(MAKE) -C ..

$(TARGET): main.cpp ../OpenPGP.h libs
	$(CXX) $(CXXFLAGS) main.cpp $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

clean-all: clean
	$(MAKE) clean -C ..