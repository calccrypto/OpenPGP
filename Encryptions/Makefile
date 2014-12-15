# Encryptions Makefile
CXX?=g++
LDFLAGS=
CXXFLAGS=-std=c++11 -Wall -c

debug: CXXFLAGS += -g
debug: all

all: SymAlg.o AES.o Blowfish.o Camellia.o CAST128.o DES.o IDEA.o TDES.o Twofish.o

SymAlg.o: SymAlg.h SymAlg.cpp
	$(CXX) $(CXXFLAGS) SymAlg.cpp

AES.o: AES.h AES.cpp ../common/cryptomath.h SymAlg.h AES_Const.h
	$(CXX) $(CXXFLAGS) AES.cpp

Blowfish.o: Blowfish.h Blowfish.cpp SymAlg.h Blowfish_Const.h
	$(CXX) $(CXXFLAGS) Blowfish.cpp

Camellia.o: Camellia.cpp Camellia.h Camellia_Const.h ../common/integer.h ../common/cryptomath.h SymAlg.h
	$(CXX) $(CXXFLAGS) Camellia.cpp

CAST128.o: CAST128.h CAST128.cpp ../common/cryptomath.h SymAlg.h CAST_Const.h CAST128_Const.h
	$(CXX) $(CXXFLAGS) CAST128.cpp

DES.o: DES.h DES.cpp SymAlg.h DES_Const.h
	$(CXX) $(CXXFLAGS) DES.cpp

IDEA.o: IDEA.h IDEA.cpp ../common/cryptomath.h SymAlg.h
	$(CXX) $(CXXFLAGS) IDEA.cpp

TDES.o: TDES.h TDES.cpp DES.h SymAlg.h
	$(CXX) $(CXXFLAGS) TDES.cpp

Twofish.o: Twofish.h Twofish.cpp SymAlg.h Twofish_Const.h
	$(CXX) $(CXXFLAGS) Twofish.cpp

clean:
	rm -f *.o
