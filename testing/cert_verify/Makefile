LIBRESWANSRCDIR=$(shell cd ../..; pwd)
UNITTEST=verify
CFLAGS+=${NSSFLAGS}
SOURCES1=verify.c
verify: ${SOURCES1}
programs checkprograms: ${UNITTEST}
	@true
include ${LIBRESWANSRCDIR}/programs/Makefile.program
