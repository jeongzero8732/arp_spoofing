TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        main.cpp \
        make_packet.cpp \
        packet_detail.cpp \
        packet_handle.cpp

HEADERS += \
    make_packet.h \
    packet_detail.h \
    packet_handle.h \
    packet_header.h
