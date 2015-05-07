UNITTEST=calc-reciprocal
CFLAGS=-DUSE_3DES -I${LIBRESWANSRCDIR}/programs/pluto

SOURCES=calc-reciprocal.c ${LIBRESWANSRCDIR}/programs/pluto/hmac.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypto.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/ike_alg.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypt_utils.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypt_dh.c

calc-reciprocal: ${SOURCES}

programs checkprograms: ${UNITTEST}
	@true

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif
