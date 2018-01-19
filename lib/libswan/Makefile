# Libreswan library

# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2017 Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

#
# XXX:
#
# Because libswan's Makefile tests USE_... variables, defined in
# config.mk, using "ifeq", it needs to include that file early.
#
# Instead:
#
# - replace the code with '$(call if-enabled)'.
#
# - move the optional files to their own library?
#

ifndef top_srcdir
include ../../mk/dirs.mk
endif
include $(top_srcdir)/mk/config.mk

LIB = libswan.a

OBJS += x509dn.o asn1.o oid.o

OBJS += addrtoa.o addrtot.o addrtypeof.o alg_info.o esp_info.o anyaddr.o \
	constants.o datatot.o \
	alloc.o diag.o \
	goodmask.o id.o initaddr.o initsaid.o initsubnet.o \
	iprange.o \
        keyblobtoid.o \
	kernel_alg.o lex.o \
	lswconf.o \
	lswfips.o \
	rangetosubnet.o sameaddr.o \
	satot.o secrets.o subnetof.o subnettoa.o subnettot.o \
	subnettypeof.o ttoaddr.o ttodata.o ttoprotoport.o \
	ttorange.o ttosa.o ttosubnet.o ttoul.o ultot.o \
	secitem_chunk.o \
	base64_rsa_pubkey.o \
	lswnss.o \
	lsw_passert_fail.o \
	libreswan_log.o \
	libreswan_loglog.o \
	alg_byname.o

OBJS += ip_address.o

OBJS += lmod.o
OBJS += deltatime.o
OBJS += realtime.o
OBJS += monotime.o

OBJS += debug_enum_names.o
OBJS += libreswan_DBG_dump.o
OBJS += libreswan_DBG_log.o

OBJS += lswlog.o
OBJS += lswlog_dbg.o
OBJS += lswlog_nss_error.o
OBJS += lswlog_nss_ckm.o
OBJS += lswlog_nss_ckf.o
OBJS += lswlog_nss_cka.o
OBJS += lswlog_source_line.o
OBJS += lswlog_sanitized.o
OBJS += lswlog_errno.o
OBJS += lswlog_bytes.o
OBJS += lswlog_enum_lset_short.o
OBJS += lswlog_realtime.o
OBJS += lswlog_deltatime.o
OBJS += lswlog_monotime.o
OBJS += lswlog_ip.o
OBJS += lswlog_sensitive_ip.o
OBJS += lswlog_to_file_stream.o
OBJS += lswlog_pexpect.o
OBJS += lswlog_passert.o

# Crypto code:
#
# XXX: More is comming as it gets cleaned up and made more library
# like.

# not much left using this
CFLAGS += -I$(top_srcdir)/lib/libcrypto

OBJS += ike_alg_desc.o
ifeq ($(USE_3DES),true)
OBJS += ike_alg_3des.o
endif
OBJS += ike_alg_aes.o
OBJS += ike_alg_camellia.o
ifeq ($(USE_CAST),true)
OBJS += ike_alg_cast.o
endif
OBJS += ike_alg_dh.o
OBJS += ike_alg_md5.o
OBJS += ike_alg_null.o
ifeq ($(USE_RIPEMD),true)
OBJS += ike_alg_ripemd.o
endif
ifeq ($(USE_SERPENT),true)
OBJS += ike_alg_serpent.o
endif
OBJS += ike_alg_sha1.o
OBJS += ike_alg_sha2.o
ifeq ($(USE_TWOFISH),true)
OBJS += ike_alg_twofish.o
endif

ifeq ($(NSS_REQ_AVA_COPY),true)
OBJS += nss_copies.o
endif

ifeq ($(USE_UNBOUND_EVENT_H_COPY),true)
CFLAGS+=-I${LIBRESWANSRCDIR}/include/unbound
endif

ifeq ($(USE_DNSSEC),true)
OBJS += unbound.o
endif

OBJS += sanitizestring.o pfkey_print.o pfkey_sock.o pfkey_error.o

ifeq ($(USE_KLIPS),true)
CFLAGS += -DKLIPS
endif

ifeq ($(USE_PFKEYv2),true)
CFLAGS += -DPFKEYV2
OBJS += pfkey_v2_build.o pfkey_v2_ext_bits.o pfkey_v2_parse.o
OBJS += pfkey_v2_debug.o
endif

CFLAGS+=-I${LIBRESWANSRCDIR}/lib/libcrypto/libsha2
CFLAGS+=-I${LIBRESWANSRCDIR}/lib/libcrypto/libaes_xcbc

KLIPSSRCDIR?=${LIBRESWANSRCDIR}/linux/net/ipsec

VPATH+= ${KLIPSSRCDIR}

# Original flags; this is a mess.
CFLAGS+=${PORTINCLUDE} -I. -I${KLIPSSRCDIR} -I${KLIPSINC}
CFLAGS+=-I${LIBRESWANSRCDIR}
CFLAGS+= $(NSSFLAGS)
CFLAGS+=-I${LIBRESWANSRCDIR}/include ${PORTINCLUDE}
# XXX: hack until everything uses a consistent .c.o rule
CFLAGS+=$(USERLAND_CFLAGS)
CFLAGS+=${CROSSFLAGS}

ifeq ($(NSS_REQ_AVA_COPY),true)
CFLAGS+=-DNSS_REQ_AVA_COPY
endif

OBJS += $(abs_builddir)/version.o

include $(top_srcdir)/mk/library.mk

# build version.c using version number from Makefile.ver
$(abs_builddir)/version.c: ${KLIPSSRCDIR}/version.in.c $(top_srcdir)/Makefile.ver
	rm -f $@.tmp
	sed -e '/"/s/@IPSECVERSION@/$(IPSECVERSION)/' \
	    -e '/"/s/@IPSECVIDVERSION@/$(IPSECVIDVERSION)/' \
	    ${KLIPSSRCDIR}/version.in.c \
	    > $@.tmp
	mv $@.tmp $@

# developer-only stuff

test-%: %.c
	${CC} ${CFLAGS} -D`echo $* | tr 'a-z' 'A-Z'`_MAIN $*.c -o test-$*

l:
	$(MAKE) $(LIB) ARFLAGS=crv CFLAGS=-O
	$(RANLIB) $(LIB)

t:	$(LIB)
	ln -f -s ${KLIPSSRCDIR}/ttosubnet.c try1a.c
	${CC} ${CFLAGS} -DTTOSUBNET_MAIN try1a.c $(LIB) -o try1a
	./try1a -r
	ln -f -s ${KLIPSSRCDIR}/ttodata.c try2.c
	${CC} ${CFLAGS} -DTTODATA_MAIN try2.c $(LIB) -o try2
	./try2 -r
	ln -f -s ${KLIPSSRCDIR}/ttosa.c try4a.c
	${CC} ${CFLAGS} -DTTOSA_MAIN try4a.c $(LIB) -o try4a
	./try4a -r
	ln -f -s ${KLIPSSRCDIR}/rangetosubnet.c try6.c
	${CC} ${CFLAGS} -DRANGETOSUBNET_MAIN try6.c $(LIB) -o try6
	./try6 -r
	ln -f -s ${KLIPSSRCDIR}/addrtot.c try7.c
	${CC} ${CFLAGS} -DADDRTOT_MAIN try7.c $(LIB) -o try7
	./try7 -r
