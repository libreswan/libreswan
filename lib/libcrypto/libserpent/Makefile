ifndef top_srcdir
include ../../../mk/objdir.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk

OBJS=serpent.o serpent_cbc.o
LIBRARY=crypto/libserpent
LIB=libserpent.a
ONEFILE=serpent.h
INCLUDES+=-I${SRCDIR}../include

include $(top_srcdir)/mk/library.mk
