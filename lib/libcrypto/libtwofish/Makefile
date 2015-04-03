
OBJS := twofish.o twofish_cbc.o

ONEFILE=twofish.c
LIBRARY=crypto/libtwofish
LIB=libtwofish.a
INCLUDES+=-I${SRCDIR}../include

ifdef top_srcdir
include $(top_srcdir)/mk/library.mk
else
include ../../../mk/library.mk
endif
