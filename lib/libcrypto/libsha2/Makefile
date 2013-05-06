LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := sha2.o

ONEFILE=sha2.c
LIBRARY=crypto/libsha2
LIB=libsha2.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library

