UNITTEST=modp-case1
CFLAGS=-DUSE_3DES -I${LIBRESWANSRCDIR}/programs/pluto

SOURCES1=modp-case0.c
SOURCES1=modp-case1.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/vulcan/vulcanpk_funcs.c

modp-case0: ${SOURCES0} ${SOURCES}

modp-case1: ${SOURCES1} ${SOURCES}

programs checkprograms: ${UNITTEST}
	@true

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif
