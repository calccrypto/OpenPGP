# OpenPGP testcases Makefile
CC=g++
LFLAGS=-lgmp -lgmpxx -lpthread
CFLAGS=-std=c++11 -Wall -c -pthread -I../gtest-1.7.0/include -I../..

debug: CFLAGS += -g
debug: all

all: test_aes128_ecb.o test_aes192_ecb.o test_aes256_ecb.o \
     test_blowfish_ecb.o test_cast128_ecb.o test_idea_ecb.o \
     test_tripledes_ecb.o test_md5.o test_ripemd160.o test_sha1.o \
     test_sha224.o test_sha256.o test_sha384.o test_sha512.o

test_aes128_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_aes128_ecb.cpp

test_aes192_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_aes192_ecb.cpp

test_aes256_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_aes256_ecb.cpp

test_blowfish_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_blowfish_ecb.cpp

test_cast128_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_cast128_ecb.cpp

test_idea_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_idea_ecb.cpp

test_tripledes_ecb.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_tripledes_ecb.cpp

test_md5.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_md5.cpp

test_ripemd160.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_ripemd160.cpp

test_sha1.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_sha1.cpp

test_sha224.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_sha224.cpp

test_sha256.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_sha256.cpp

test_sha384.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_sha384.cpp

test_sha512.o:
	$(CC) $(CFLAGS) $(LFLAGS) test_sha512.cpp

clean:
	rm -f *.o

