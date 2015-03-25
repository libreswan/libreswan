ifndef top_srcdir
include ../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk

OBJS := twofish.o twofish_cbc.o

ONEFILE=twofish.c
LIBRARY=crypto/libtwofish
LIB=libtwofish.a
INCLUDES+=-I${SRCDIR}../include

include $(top_srcdir)/mk/library.mk
