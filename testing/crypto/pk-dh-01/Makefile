OPENSWANSRCDIR=$(shell cd ../../..; pwd)

UNITTEST=pk-dh
CFLAGS=-DUSE_3DES -I${OPENSWANSRCDIR}/programs/pluto

programs checkprograms: ${UNITTEST}
	@true

include ${OPENSWANSRCDIR}/programs/Makefile.program


