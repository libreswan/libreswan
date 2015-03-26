ifndef top_srcdir
include ../../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk

OBJS := aes_xcbc.o

ONEFILE=aes_xcbc.c
LIBRARY=crypto/libaes_xcbc
LIB=libaes_xcbc.a
INCLUDES+=-I${SRCDIR}../include

include $(top_srcdir)/mk/library.mk
