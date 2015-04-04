OBJS := aes_xcbc.o

ONEFILE=aes_xcbc.c
LIBRARY=crypto/libaes_xcbc
LIB=libaes_xcbc.a
INCLUDES+=-I${SRCDIR}../include

ifdef top_srcdir
include $(top_srcdir)/mk/library.mk
else
include ../../../mk/library.mk
endif
