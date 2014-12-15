# Hashes Makefile
CXX?=g++
LDFLAGS=
CXXFLAGS=-std=c++11 -Wall -c

debug: CXXFLAGS += -g
debug: all

all: Hash.o Hashes.o MD5.o RIPEMD160.o SHA1.o SHA224.o SHA256.o SHA2_Functions.o SHA384.o SHA512.o

Hash.o: Hash.h Hash.cpp ../common/includes.h
	$(CXX) $(CXXFLAGS) Hash.cpp

Hashes.o: Hashes.h Hashes.cpp ../common/cryptomath.h ../common/includes.h Hash.h RIPEMD160.h SHA1.h SHA256.h SHA224.h SHA512.h SHA384.h
	$(CXX) $(CXXFLAGS) Hashes.cpp

MD5.o: MD5.h MD5.cpp ../common/cryptomath.h ../common/includes.h Hash.h MD5_Const.h
	$(CXX) $(CXXFLAGS) MD5.cpp

RIPEMD160.o: RIPEMD160.h RIPEMD160.cpp ../common/cryptomath.h ../common/includes.h Hash.h RIPEMD_Const.h RIPEMD160_Const.h
	$(CXX) $(CXXFLAGS) RIPEMD160.cpp

SHA1.o: SHA1.h SHA1.cpp ../common/cryptomath.h ../common/includes.h Hash.h
	$(CXX) $(CXXFLAGS) SHA1.cpp

SHA224.o: SHA224.h SHA224.cpp SHA256.h
	$(CXX) $(CXXFLAGS) SHA224.cpp

SHA256.o: SHA256.h SHA256.cpp ../common/cryptomath.h ../common/includes.h Hash.h SHA2_Functions.h SHA256_Const.h
	$(CXX) $(CXXFLAGS) SHA256.cpp

SHA2_Functions.o: SHA2_Functions.h SHA2_Functions.cpp
	$(CXX) $(CXXFLAGS) SHA2_Functions.cpp

SHA384.o: SHA384.h SHA384.cpp SHA512.h
	$(CXX) $(CXXFLAGS) SHA384.cpp

SHA512.o: SHA512.h SHA512.cpp ../common/cryptomath.h ../common/includes.h Hash.h SHA2_Functions.h SHA512_Const.h
	$(CXX) $(CXXFLAGS) SHA512.cpp

clean:
	rm -f *.o
