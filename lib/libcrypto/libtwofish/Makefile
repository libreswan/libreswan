LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
SRCDIR?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := twofish.o twofish_cbc.o

ONEFILE=twofish.c
LIBRARY=crypto/libtwofish
LIB=libtwofish.a
INCLUDES+=-I${SRCDIR}../include

include ${SRCDIR}../../Makefile.library

