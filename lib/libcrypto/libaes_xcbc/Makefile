LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := aes_xcbc.o

ONEFILE=aes_xcbc.c
LIBRARY=crypto/libaes_xcbc
LIB=libaes_xcbc.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library

