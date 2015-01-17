LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
SRCDIR?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := sha1.o

ONEFILE=sha1.c
LIBRARY=crypto/libsha1
LIB=libsha1.a

include ${SRCDIR}../../Makefile.library
