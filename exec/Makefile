# OpenPGP executable Makefile
CC=g++
LFLAGS=
BFLAGS=-std=c++11 -Wall
CFLAGS= $(BFLAGS) -c
TARGET=OpenPGP

debug: BFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs

libs:
	$(MAKE) -C ..

$(TARGET): main.cpp libs
	$(CC) $(BFLAGS) main.cpp ../*.o ../*/*.o -o $(TARGET)

clean:
	rm -f ../*.o ../*/*.o $(TARGET)