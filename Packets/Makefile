# Packets Makefile
CC=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c
debug: BFLAGS += -g
debug: all

all: packets.o packet.o Tag0.o Tag1.o Tag2.o Tag3.o Tag4.o Tag5.o Tag6.o Tag7.o Tag8.o Tag9.o Tag10.o Tag11.o Tag12.o Tag13.o Tag14.o Tag17.o Tag18.o Tag19.o

packets.o: packet.h packets.cpp packet.h Tag0.h Tag1.h Tag2.h Tag3.h Tag4.h Tag5.h Tag6.h Tag7.h Tag8.h Tag9.h Tag10.h Tag11.h Tag12.h Tag13.h Tag14.h Tag17.h Tag18.h Tag19.h
	$(CC) $(CFLAGS) packets.cpp

packet.o: packet.h packet.cpp ../common/includes.h ../consts.h ../mpi.h ../pgptime.h ../s2k.h
	$(CC) $(CFLAGS) packet.cpp

Tag0.o: Tag0.h Tag0.cpp packet.h
	$(CC) $(CFLAGS) Tag0.cpp

Tag1.o: Tag1.h Tag1.cpp packet.h
	$(CC) $(CFLAGS) Tag1.cpp

Tag2.o: Tag2.h Tag2.cpp ../Subpackets/subpackets.h packet.h Tag6.h
	$(CC) $(CFLAGS) Tag2.cpp

Tag3.o: Tag3.h Tag3.cpp ../cfb.h packet.h
	$(CC) $(CFLAGS) Tag3.cpp

Tag4.o: Tag4.h Tag4.cpp packet.h
	$(CC) $(CFLAGS) Tag4.cpp

Tag5.o: Tag5.h Tag5.cpp Tag6.h
	$(CC) $(CFLAGS) Tag5.cpp

Tag6.o: Tag6.h Tag6.cpp packet.h
	$(CC) $(CFLAGS) Tag6.cpp $(LFLAGS)

Tag7.o: Tag7.h Tag7.cpp Tag5.h
	$(CC) $(CFLAGS) Tag7.cpp

Tag8.o: Tag8.h Tag8.cpp packet.h
	$(CC) $(CFLAGS) Tag8.cpp

Tag9.o: Tag9.h Tag9.cpp packet.h
	$(CC) $(CFLAGS) Tag9.cpp

Tag10.o: Tag10.h Tag10.cpp packet.h
	$(CC) $(CFLAGS) Tag10.cpp

Tag11.o: Tag11.h Tag11.cpp packet.h
	$(CC) $(CFLAGS) Tag11.cpp

Tag12.o: Tag12.h Tag12.cpp packet.h
	$(CC) $(CFLAGS) Tag12.cpp

Tag13.o: Tag13.h Tag13.cpp packet.h
	$(CC) $(CFLAGS) Tag13.cpp

Tag14.o: Tag14.h Tag14.cpp Tag6.h
	$(CC) $(CFLAGS) Tag14.cpp

Tag17.o: Tag17.h Tag17.cpp ../Subpackets/subpackets.h packet.h
	$(CC) $(CFLAGS) Tag17.cpp

Tag18.o: Tag18.h Tag18.cpp packet.h
	$(CC) $(CFLAGS) Tag18.cpp

Tag19.o: Tag19.h Tag19.cpp packet.h
	$(CC) $(CFLAGS) Tag19.cpp

clean:
	rm -f *.o
