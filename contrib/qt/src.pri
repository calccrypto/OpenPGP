CONFIG += c++11 object_parallel_to_source

INCLUDEPATH += $$PWD/../../

SOURCES += \
    $$PWD/../../src/common/*.cpp \
    $$PWD/../../src/Compress/*.cpp \
    $$PWD/../../src/Encryptions/*.cpp \
    $$PWD/../../src/Hashes/*.cpp \
    $$PWD/../../src/Misc/*.cpp \
    $$PWD/../../src/PKA/*.cpp \
    $$PWD/../../src/Packets/*.cpp \
    $$PWD/../../src/RNG/*.cpp \
    $$PWD/../../src/Subpackets/Tag2/*.cpp \
    $$PWD/../../src/Subpackets/Tag17/*.cpp \
    $$PWD/../../src/Subpackets/*.cpp \
    $$PWD/../../src/*.cpp

HEADERS += \
    $$PWD/../../include/common/*.h \
    $$PWD/../../include/Compress/*.h \
    $$PWD/../../include/Encryptions/*.h \
    $$PWD/../../include/Hashes/*.h \
    $$PWD/../../include/Misc/*.h \
    $$PWD/../../include/PKA/*.h \
    $$PWD/../../include/Packets/*.h \
    $$PWD/../../include/RNG/*.h \
    $$PWD/../../include/Subpackets/Tag2/*.h \
    $$PWD/../../include/Subpackets/Tag17/*.h \
    $$PWD/../../include/Subpackets/*.h \
    $$PWD/../../include/*.h
