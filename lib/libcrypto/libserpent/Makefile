OBJS=serpent.o serpent_cbc.o
LIBRARY=crypto/libserpent
LIB=libserpent.a
ONEFILE=serpent.h
INCLUDES+=-I${SRCDIR}../include

ifdef top_srcdir
include $(top_srcdir)/mk/library.mk
else
include ../../../mk/library.mk
endif
