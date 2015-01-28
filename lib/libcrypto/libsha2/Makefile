LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
SRCDIR?=$(shell pwd)/

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := sha2.o

ONEFILE=sha2.c
LIBRARY=crypto/libsha2
LIB=libsha2.a
INCLUDES+=-I${SRCDIR}../include

include ${SRCDIR}../../Makefile.library

