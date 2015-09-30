UNITTEST=psk-v2
CFLAGS=-DUSE_3DES
INCLUDES=-I${SRCDIR}${LIBRESWANSRCDIR}/programs/pluto
INCLUDES+=-I${SRCDIR}${LIBRESWANSRCDIR}/testing/lib/libpluto

SOURCES=psk-v2.c packetsI1psk.c

# what we are testing
OBJS+=${OBJDIRTOP}/programs/pluto/ikev2_psk.o

# for load_preshared_secrets()
OBJS+=${OBJDIRTOP}/programs/pluto/keys.o

# for cryptodev.
OBJS+=${OBJDIRTOP}/programs/pluto/ocf_pk.o

# for whack_process
OBJS+=${OBJDIRTOP}/programs/pluto/rcv_whack.o
# ... which needs myid
OBJS+=${OBJDIRTOP}/programs/pluto/myid.o
# ... and needs load_groups
OBJS+=${OBJDIRTOP}/programs/pluto/foodgroups.o
OBJS+=${OBJDIRTOP}/programs/pluto/connections.o
OBJS+=${OBJDIRTOP}/programs/pluto/hostpair.o
OBJS+=${OBJDIRTOP}/programs/pluto/virtual.o

OBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_status.o
OBJS+=${OBJDIRTOP}/programs/pluto/plutoalg.o
OBJS+=${OBJDIRTOP}/programs/pluto/spdb.o
OBJS+=${OBJDIRTOP}/programs/pluto/db_ops.o

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

PROGRAM=psk-v2

programs checkprograms: ${UNITTEST}
	@true

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif

packetsI1psk.c: ../../lib/libpluto/lib-parentI1psk/parentI1psk.pcap
	../../utils/pcap2skb/pcap2skb $< >packetsI1psk.c

#psk-v2.o: ${SOURCES}

psk-v2: psk-v2.o $(OBJS) ${LIBS}
	$(CC) $(CFLAGS) -o $@ $@.o ${OBJS} ${PROGLIBS} $(LDFLAGS) $(LDLIBS) $(USERLINK)
