CONFIG += c++11 object_parallel_to_source

INCLUDEPATH += $$PWD/../

SOURCES += \
    $$PWD/../common/*.cpp \
    $$PWD/../Compress/*.cpp \
    $$PWD/../Encryptions/*.cpp \
    $$PWD/../Hashes/*.cpp \
    $$PWD/../Misc/*.cpp \
    $$PWD/../PKA/*.cpp \
    $$PWD/../Packets/*.cpp \
    $$PWD/../RNG/*.cpp \
    $$PWD/../Subpackets/Tag2/*.cpp \
    $$PWD/../Subpackets/Tag17/*.cpp \
    $$PWD/../Subpackets/*.cpp \
    $$PWD/../*.cpp

HEADERS += \
    $$PWD/../common/*.h \
    $$PWD/../Compress/*.h \
    $$PWD/../Encryptions/*.h \
    $$PWD/../Hashes/*.h \
    $$PWD/../Misc/*.h \
    $$PWD/../PKA/*.h \
    $$PWD/../Packets/*.h \
    $$PWD/../RNG/*.h \
    $$PWD/../Subpackets/Tag2/*.h \
    $$PWD/../Subpackets/Tag17/*.h \
    $$PWD/../Subpackets/*.h \
    $$PWD/../*.h

