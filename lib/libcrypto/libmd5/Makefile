LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := md5.o

ONEFILE=md5.c
LIBRARY=crypto/libmd5
LIB=libmd5.a

include ${srcdir}../../Makefile.library
