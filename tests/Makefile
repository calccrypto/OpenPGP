# OpenPGP test Makefile
CXX?=g++
CXXFLAGS=-std=c++11 -Wall -I../../googletest/googletest/include
LDFLAGS=-lOpenPGP -lgmpxx -lgmp -lbz2 -lz -lgtest -lpthread -L../../googletest/googlemock/gtest -L..
AR=ar
TARGET=tests

include testcases/objects.mk
include testcases/common/objects.mk
include testcases/Compress/objects.mk
include testcases/Encryptions/objects.mk
include testcases/exec/objects.mk
include testcases/exec/modules/objects.mk
include testcases/Hashes/objects.mk
include testcases/Misc/objects.mk
include testcases/PKA/objects.mk

all: $(TARGET)

gpg-compatible: CXXFLAGS += -DGPG_COMPATIBLE
gpg-compatible: all

debug: CXXFLAGS += -g
debug: all

gpg-debug: CXXFLAGS += -DGPG_COMPATIBLE
gpg-debug: debug

.PHONY: testcases modules run clean clean-testcases clean-lib clean-all

../libOpenPGP.a:
	$(MAKE) $(MAKECMDGOALS) -C ..

testcases:
	$(MAKE) $(MAKECMDGOALS) -C testcases

modules: ../exec/modules/module.o
	$(MAKE) -C ../exec/modules

$(TARGET): main.cc ../libOpenPGP.a testcases
	$(CXX) $(CXXFLAGS) main.cc $(addprefix testcases/, $(TESTCASES_OBJECTS)) $(addprefix testcases/common/, $(COMMON_TESTCASES_OBJECTS)) $(addprefix testcases/Compress/, $(COMPRESS_TESTCASES_OBJECTS)) $(addprefix testcases/Encryptions/, $(ENCRYPTIONS_TESTCASES_OBJECTS)) $(addprefix testcases/exec/, $(EXEC_TESTCASES_OBJECTS)) $(addprefix testcases/exec/modules/, $(MODULES_TESTCASES_OBJECTS)) $(addprefix testcases/Hashes/, $(HASHES_TESTCASES_OBJECTS)) $(addprefix testcases/Misc/, $(MISC_TESTCASES_OBJECTS)) $(addprefix testcases/PKA/, $(PKA_TESTCASES_OBJECTS)) ../exec/modules/module.o $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

clean-all: clean
	$(MAKE) clean -C testcases
	$(MAKE) clean -C ..
