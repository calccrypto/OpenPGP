# OpenPGP executable Makefile
CC=g++
LFLAGS=-lgmpxx -lgmp
CFLAGS=-std=c++11 -Wall
TARGET=OpenPGP

debug: BFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: libs

libs:
	$(MAKE) -C ..

$(TARGET): main.cpp libs
	$(CC) $(CFLAGS) main.cpp ../*.o ../*/*.o $(LFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)
	$(MAKE) -C .. clean
