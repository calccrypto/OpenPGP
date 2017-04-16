# OpenPGP executable Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall
LDFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L..
TARGET=OpenPGP

include modules/objects.mk

all: $(TARGET)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: lib modules clean clean-modules clean-all

lib:
	$(MAKE) $(MAKECMDGOALS) -C ..

modules:
	$(MAKE) $(MAKECMDGOALS) -C modules

$(TARGET): main.cpp ../OpenPGP.h lib modules
	$(CXX) $(CXXFLAGS) main.cpp $(addprefix modules/, $(MODULES_OBJECTS)) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

clean-modules:
	$(MAKE) clean -C modules

clean-all: clean clean-modules
	$(MAKE) clean-all -C ..
