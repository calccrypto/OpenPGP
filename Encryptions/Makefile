# Encryptions Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: SymAlg.o AES.o Blowfish.o CAST128.o DES.o IDEA.o TDES.o

SymAlg.o: SymAlg.h SymAlg.cpp
	$(CC) $(CFLAGS) SymAlg.cpp

AES.o: AES.h AES.cpp ../common/cryptomath.h SymAlg.h AES_Const.h
	$(CC) $(CFLAGS) AES.cpp

Blowfish.o: Blowfish.h Blowfish.cpp SymAlg.h Blowfish_Const.h
	$(CC) $(CFLAGS) Blowfish.cpp

CAST128.o: CAST128.h CAST128.cpp ../common/cryptomath.h SymAlg.h CAST_Const.h CAST128_Const.h
	$(CC) $(CFLAGS) CAST128.cpp

DES.o: DES.h DES.cpp SymAlg.h DES_Const.h
	$(CC) $(CFLAGS) DES.cpp

IDEA.o: IDEA.h IDEA.cpp ../common/cryptomath.h SymAlg.h
	$(CC) $(CFLAGS) IDEA.cpp

TDES.o: TDES.h TDES.cpp DES.h SymAlg.h
	$(CC) $(CFLAGS) TDES.cpp

clean:
	rm -f *.o
