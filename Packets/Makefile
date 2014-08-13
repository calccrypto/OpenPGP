# Packets Makefile
CXX?=g++
LFLAGS=-lgmp -lgmpxx
CFLAGS=-std=c++11 -Wall -c

debug: CFLAGS += -g
debug: all

all: packet.o packets.o Partial.o s2k.o Tag0.o Tag1.o Tag2.o Tag3.o Tag4.o Tag5.o Tag6.o Tag7.o Tag8.o Tag9.o Tag10.o Tag11.o Tag12.o Tag13.o Tag14.o Tag17.o Tag18.o Tag19.o Tag60.o Tag61.o Tag62.o Tag63.o

packet.o: packet.h packet.cpp ../common/includes.h ../Hashes/Hashes.h ../consts.h ../mpi.h ../pgptime.h
	$(CXX) $(CFLAGS) packet.cpp

packets.o: packets.h packets.cpp packet.h Partial.h Tag0.h Tag1.h Tag2.h Tag3.h Tag4.h Tag5.h Tag6.h Tag7.h Tag8.h Tag9.h Tag10.h Tag11.h Tag12.h Tag13.h Tag14.h Tag17.h Tag18.h Tag19.h Tag60.h Tag61.h Tag62.h Tag63.h
	$(CXX) $(CFLAGS) packets.cpp

Partial.o: Partial.h Partial.cpp packet.h
	$(CXX) $(CFLAGS) Partial.cpp

s2k.o: s2k.h s2k.cpp ../common/includes.h ../Hashes/Hashes.h ../consts.h
	$(CXX) $(CFLAGS) s2k.cpp

Tag0.o: Tag0.h Tag0.cpp packet.h
	$(CXX) $(CFLAGS) Tag0.cpp

Tag1.o: Tag1.h Tag1.cpp packet.h
	$(CXX) $(CFLAGS) Tag1.cpp

Tag2.o: Tag2.h Tag2.cpp ../Subpackets/subpackets.h packet.h
	$(CXX) $(CFLAGS) Tag2.cpp

Tag3.o: Tag3.h Tag3.cpp ../cfb.h packet.h s2k.h
	$(CXX) $(CFLAGS) Tag3.cpp

Tag4.o: Tag4.h Tag4.cpp packet.h
	$(CXX) $(CFLAGS) Tag4.cpp

Tag5.o: Tag5.h Tag5.cpp s2k.h Tag6.h
	$(CXX) $(CFLAGS) Tag5.cpp

Tag6.o: Tag6.h Tag6.cpp packet.h
	$(CXX) $(CFLAGS) Tag6.cpp

Tag7.o: Tag7.h Tag7.cpp Tag5.h Tag14.h
	$(CXX) $(CFLAGS) Tag7.cpp

Tag8.o: Tag8.h Tag8.cpp ../Compress/Compress.h ../PGPMessage.h packet.h
	$(CXX) $(CFLAGS) Tag8.cpp

Tag9.o: Tag9.h Tag9.cpp packet.h
	$(CXX) $(CFLAGS) Tag9.cpp

Tag10.o: Tag10.h Tag10.cpp packet.h
	$(CXX) $(CFLAGS) Tag10.cpp

Tag11.o: Tag11.h Tag11.cpp packet.h
	$(CXX) $(CFLAGS) Tag11.cpp

Tag12.o: Tag12.h Tag12.cpp packet.h
	$(CXX) $(CFLAGS) Tag12.cpp

Tag13.o: Tag13.h Tag13.cpp packet.h
	$(CXX) $(CFLAGS) Tag13.cpp

Tag14.o: Tag14.h Tag14.cpp Tag6.h
	$(CXX) $(CFLAGS) Tag14.cpp

Tag17.o: Tag17.h Tag17.cpp ../Subpackets/subpackets.h packet.h
	$(CXX) $(CFLAGS) Tag17.cpp

Tag18.o: Tag18.h Tag18.cpp packet.h
	$(CXX) $(CFLAGS) Tag18.cpp

Tag19.o: Tag19.h Tag19.cpp packet.h
	$(CXX) $(CFLAGS) Tag19.cpp

Tag60.o: Tag60.h Tag60.cpp packet.h
	$(CXX) $(CFLAGS) Tag60.cpp

Tag61.o: Tag61.h Tag61.cpp packet.h
	$(CXX) $(CFLAGS) Tag61.cpp

Tag62.o: Tag62.h Tag62.cpp packet.h
	$(CXX) $(CFLAGS) Tag62.cpp

Tag63.o: Tag63.h Tag63.cpp packet.h
	$(CXX) $(CFLAGS) Tag63.cpp

clean:
	rm -f *.o
