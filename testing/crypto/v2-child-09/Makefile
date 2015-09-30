UNITTEST=v2-child
CFLAGS=-DUSE_3DES
INCLUDES=-I${SRCDIR}${LIBRESWANSRCDIR}/programs/pluto
INCLUDES+=-I${SRCDIR}${LIBRESWANSRCDIR}/testing/lib/libpluto

SOURCES=v2-child.c

# for load_preshared_secrets()
OBJS+=${OBJDIRTOP}/programs/pluto/keys.o

# for cryptodev.
OBJS+=${OBJDIRTOP}/programs/pluto/ocf_pk.o

OBJS+=${OBJDIRTOP}/programs/pluto/ikev2_prfplus.o
OBJS+=${OBJDIRTOP}/programs/pluto/ikev2_crypto.o

OBJS+=${OBJDIRTOP}/programs/pluto/hmac.o
OBJS+=${OBJDIRTOP}/programs/pluto/crypto.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_blowfish.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_twofish.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_serpent.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_aes.o
OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_sha2.o
OBJS+=${OBJDIRTOP}/programs/pluto/kernel_noklips.o

OBJS+=${PLUTOLIB}
PROGLIBS=
EXTRALIBS+=${PLUTOLIB} ${CRYPTOLIBS} ${WHACKLIB}

PROGRAM=v2-child

programs checkprograms: ${UNITTEST}
	@true

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif

#rsa-v2.o: ${SOURCES}

v2-child: v2-child.o $(OBJS) ${LIBS}
	$(CC) $(CFLAGS) -o $@ $@.o ${OBJS} ${PROGLIBS} $(LDFLAGS) $(LDLIBS) $(USERLINK)





