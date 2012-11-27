LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := lswcrypto.o
ifeq ($(HAVE_OCF),true)
OBJS += cryptodev.o
CFLAGS += -DHAVE_OCF=1
endif

ONEFILE=lswcrypto.c
LIBRARY=crypto/liblswcrypto
LIB=liblswcrypto.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library
