# Hashes Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: Hash.o Hashes.o MD5.o RIPEMD160.o SHA1.o SHA224.o SHA256.o SHA2_Functions.o SHA384.o SHA512.o

Hash.o: Hash.h Hash.cpp ../common/includes.h
	$(CC) $(CFLAGS) Hash.cpp

Hashes.o: Hashes.h Hashes.cpp ../common/cryptomath.h ../common/includes.h Hash.h RIPEMD160.h SHA1.h SHA256.h SHA224.h SHA512.h SHA384.h
	$(CC) $(CFLAGS) Hashes.cpp

MD5.o: MD5.h MD5.cpp ../common/cryptomath.h ../common/includes.h Hash.h MD5_Const.h
	$(CC) $(CFLAGS) MD5.cpp

RIPEMD160.o: RIPEMD160.h RIPEMD160.cpp ../common/cryptomath.h ../common/includes.h Hash.h RIPEMD_Const.h RIPEMD160_Const.h
	$(CC) $(CFLAGS) RIPEMD160.cpp

SHA1.o: SHA1.h SHA1.cpp ../common/cryptomath.h ../common/includes.h Hash.h
	$(CC) $(CFLAGS) SHA1.cpp

SHA224.o: SHA224.h SHA224.cpp SHA256.h
	$(CC) $(CFLAGS) SHA224.cpp

SHA256.o: SHA256.h SHA256.cpp ../common/cryptomath.h ../common/includes.h Hash.h SHA2_Functions.h SHA256_Const.h
	$(CC) $(CFLAGS) SHA256.cpp

SHA2_Functions.o: SHA2_Functions.h SHA2_Functions.cpp
	$(CC) $(CFLAGS) SHA2_Functions.cpp

SHA384.o: SHA384.h SHA384.cpp SHA512.h
	$(CC) $(CFLAGS) SHA384.cpp

SHA512.o: SHA512.h SHA512.cpp ../common/cryptomath.h ../common/includes.h Hash.h SHA2_Functions.h SHA512_Const.h
	$(CC) $(CFLAGS) SHA512.cpp

clean:
	rm -f *.o
