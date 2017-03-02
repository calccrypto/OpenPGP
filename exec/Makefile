# OpenPGP executable Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall
LDFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L..
TARGET=OpenPGP

include modules/objects.mk

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: lib modules clean clean-all

lib:
	$(MAKE) -C ..

modules:
	$(MAKE) -C modules

$(TARGET): main.cpp ../OpenPGP.h lib modules
	$(CXX) $(CXXFLAGS) main.cpp $(addprefix modules/, $(MODULES_OBJECTS)) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

clean-all: clean
	$(MAKE) clean-all -C ..
	$(MAKE) clean -C modules