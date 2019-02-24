TARGET = OpenPGP
TEMPLATE = app
CONFIG -= qt

include($$PWD/OpenPGP.pri)

SOURCES += \
    $$PWD/../../src/exec/*.cpp \
    $$PWD/../../src/exec/modules/*.cpp

HEADERS += \
    $$PWD/../../include/exec/modules/*.h
