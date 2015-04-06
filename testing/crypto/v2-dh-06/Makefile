UNITTEST=pk-dh
CFLAGS=-DUSE_3DES -I${LIBRESWANSRCDIR}/programs/pluto

SOURCES=pk-dh.c ${LIBRESWANSRCDIR}/programs/pluto/hmac.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypto.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/ike_alg.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/rnd.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypt_utils.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypt_dh.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/ikev2_prfplus.c

PROGRAM=pk-dh

pk-dh: ${SOURCES}

programs checkprograms: ${UNITTEST}
	@true

check:
	../../utils/runme.sh

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif
