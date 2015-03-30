ifndef top_srcdir
include ../../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk

OBJS := sha2.o

ONEFILE=sha2.c
LIBRARY=crypto/libsha2
LIB=libsha2.a
INCLUDES+=-I${SRCDIR}../include

include $(top_srcdir)/mk/library.mk
