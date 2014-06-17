# Encryptions Makefile
CXX?=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: SymAlg.o AES.o Blowfish.o CAST128.o Camellia.o DES.o IDEA.o TDES.o

SymAlg.o: SymAlg.h SymAlg.cpp
	$(CXX) $(CFLAGS) SymAlg.cpp

AES.o: AES.h AES.cpp ../common/cryptomath.h SymAlg.h AES_Const.h
	$(CXX) $(CFLAGS) AES.cpp

Blowfish.o: Blowfish.h Blowfish.cpp SymAlg.h Blowfish_Const.h
	$(CXX) $(CFLAGS) Blowfish.cpp

Camellia.o: Camellia.cpp Camellia.h Camellia_Const.h ../common/integer.h ../common/cryptomath.h SymAlg.h
	$(CC) $(CFLAGS) Camellia.cpp

CAST128.o: CAST128.h CAST128.cpp ../common/cryptomath.h SymAlg.h CAST_Const.h CAST128_Const.h
	$(CXX) $(CFLAGS) CAST128.cpp

DES.o: DES.h DES.cpp SymAlg.h DES_Const.h
	$(CXX) $(CFLAGS) DES.cpp

IDEA.o: IDEA.h IDEA.cpp ../common/cryptomath.h SymAlg.h
	$(CXX) $(CFLAGS) IDEA.cpp

TDES.o: TDES.h TDES.cpp DES.h SymAlg.h
	$(CXX) $(CFLAGS) TDES.cpp

clean:
	rm -f *.o
