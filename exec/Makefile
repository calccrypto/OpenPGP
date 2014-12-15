# OpenPGP commandline Makefile
CXX?=g++
LDFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L..
CXXFLAGS=-std=c++11 -Wall
TARGET=OpenPGP
TABFILE=OpenPGP.sh
TABDIR=/etc/bash_completion.d
INSTALL=/usr/local

debug: CXXFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs

libs:
	$(MAKE) -C ..

$(TARGET): main.cpp ../OpenPGP.h libs
	$(CXX) $(CXXFLAGS) main.cpp $(LDFLAGS) -o $(TARGET)

install:
#	$(MAKE) -C .. install
	cp $(TARGET) $(INSTALL)/bin
	cp $(TABFILE) $(TABDIR)

uninstall:
#	$(MAKE) -C .. uninstall
	rm $(INSTALL)/bin/$(TARGET)
	rm $(TABDIR)/$(TABFILE)

clean:
	rm -f $(TARGET)
	$(MAKE) -C .. clean