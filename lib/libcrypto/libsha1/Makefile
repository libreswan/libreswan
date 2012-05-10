LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := sha1.o

ONEFILE=sha1.c
LIBRARY=crypto/libsha1
LIB=libsha1.a

CFLAGS+=-I/usr/include/nspr4 -I/usr/include/nss3

include ${srcdir}../../Makefile.library
