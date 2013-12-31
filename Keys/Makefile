# OpenPGP Types Makefile
CC=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: PGP.o PGPSignedMessage.o

PGP.o: PGP.h PGP.cpp ../common/includes.h ../Packets/packets.h ../Subpackets/subpackets.h ../consts.h ../pgptime.h ../radix64.h
	$(CC) $(CFLAGS) PGP.cpp

#PGPKey.o: PGPKey.h PGPKey.cpp PGP.h
#	$(CC) $(CFLAGS) PGPKey.cpp

#PGPMessage.o: PGPMessage.h PGPMessage.cpp PGP.h
#	$(CC) $(CFLAGS) PGPMessage.cpp

#PGPMessageX.o: PGPMessageX.h PGPMessageX.cpp PGP.h
#	$(CC) $(CFLAGS) PGPMessageX.cpp

#PGPMessageXY.o: PGPMessageXY.h PGPMessageXY.cpp PGP.h
#	$(CC) $(CFLAGS) PGPMessageXY.cpp

#PGPPrivateKey.o: PGPPrivateKey.h PGPPrivateKey.cpp PGPKey.h
#	$(CC) $(CFLAGS) PGPPrivateKey.cpp

#PGPPublicKey.o: PGPPublicKey.h PGPPublicKey.cpp PGPKey.h
#	$(CC) $(CFLAGS) PGPPublicKey.cpp

#PGPSignature.o: PGPSignature.h PGPSignature.cpp PGP.h
#	$(CC) $(CFLAGS) PGPSignature.cpp

PGPSignedMessage.o: PGPSignedMessage.h PGPSignedMessage.cpp PGP.h
	$(CC) $(CFLAGS) PGPSignedMessage.cpp

clean:
	rm -f *.o
