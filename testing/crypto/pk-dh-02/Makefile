UNITTEST=pk-dh
CFLAGS+=-DUSE_3DES -I${LIBRESWANSRCDIR}/programs/pluto

SOURCES=pk-dh.c ${LIBRESWANSRCDIR}/programs/pluto/hmac.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/vulcan/crypto_dh_vulcanpk.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/vulcan/vulcanpk_funcs.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypto.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/ike_alg.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypt_utils.c
SOURCES+=${LIBRESWANSRCDIR}/programs/pluto/crypt_dh.c

pk-dh: ${SOURCES}

programs checkprograms: ${UNITTEST}
	@true

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif
