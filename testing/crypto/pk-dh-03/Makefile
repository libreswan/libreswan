OPENSWANSRCDIR=$(shell cd ../../..; pwd)

UNITTEST=modp-case1
CFLAGS=-DUSE_3DES -I${OPENSWANSRCDIR}/programs/pluto

SOURCES1=modp-case0.c 
SOURCES1=modp-case1.c 
SOURCES+=${OPENSWANSRCDIR}/programs/pluto/vulcan/vulcanpk_funcs.c

modp-case0: ${SOURCES0} ${SOURCES}

modp-case1: ${SOURCES1} ${SOURCES}

programs checkprograms: ${UNITTEST}
	@true

include ${OPENSWANSRCDIR}/programs/Makefile.program


