LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
SRCDIR?=$(shell pwd)/

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS=serpent.o serpent_cbc.o
LIBRARY=crypto/libserpent
LIB=libserpent.a
ONEFILE=serpent.h
INCLUDES+=-I${SRCDIR}../include

include ${SRCDIR}../../Makefile.library

