# Encryptions Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: AES.o Blowfish.o CAST128.o DES.o error.o IDEA.o TDES.o

AES.o: AES.h AES.cpp ../common/cryptomath.h error.h SymAlg.h AES_Const.h
	$(CC) $(CFLAGS) AES.cpp

Blowfish.o: Blowfish.h Blowfish.cpp error.h SymAlg.h Blowfish_Const.h
	$(CC) $(CFLAGS) Blowfish.cpp

CAST128.o: CAST128.h CAST128.cpp ../common/cryptomath.h error.h SymAlg.h CAST_Const.h CAST128_Const.h
	$(CC) $(CFLAGS) CAST128.cpp

DES.o: DES.h DES.cpp error.h SymAlg.h DES_Const.h
	$(CC) $(CFLAGS) DES.cpp

error.o: error.h error.cpp ../common/includes.h
	$(CC) $(CFLAGS) error.cpp

IDEA.o: IDEA.h IDEA.cpp ../common/cryptomath.h error.h SymAlg.h
	$(CC) $(CFLAGS) IDEA.cpp

TDES.o: TDES.h TDES.cpp DES.h error.h SymAlg.h
	$(CC) $(CFLAGS) TDES.cpp

clean:
	rm -f *.o
