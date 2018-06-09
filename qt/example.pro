TARGET = OpenPGP
TEMPLATE = app
CONFIG -= qt

include($$PWD/OpenPGP.pri)

SOURCES += \
    $$PWD/../exec/*.cpp \
    $$PWD/../exec/modules/*.cpp

HEADERS += \
    $$PWD/../exec/modules/*.h

