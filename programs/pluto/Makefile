# Pluto Makefile
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001  D. Hugh Redelmeier
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
# RCSID $Id: Makefile,v 1.189.2.3 2005/08/12 01:12:38 ken Exp $

# All of the USE_ and HAVE_ variables are controlled from openswan/Makefile.inc


# relative path to top directory of Openswan source
# Note: referenced in ${OPENSWANSRCDIR}/Makefile.inc
OPENSWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=.

include ${OPENSWANSRCDIR}/Makefile.inc

ifeq ($(USE_LDAP),true)
# Everyone (should) be using LDAPv3, however LDAP_VERSION=2 is an option
# if you require LDAPv2 
LDAP_VERSION=3
endif

# Use SMARTCARDS
ifeq ($(USE_SMARTCARD),true)
SMARTCARD=1
endif


# whether or not to enable aggressive mode exchanges.
ifeq ($(USE_AGGRESSIVE),true)
AGGRESSIVE=1
endif

ifeq ($(USE_HWRANDOM),true)
HW_DEFS+=-DHWRANDOM
endif

ifeq ($(USE_XAUTH),true)
XAUTH=1
# compile with PAM support will increase the size of the distribution
# and thus it may not be the best solution for embeded systems. XAUTH
# will use MD5/DES crypt() lib and a password file by default.
ifeq ($(USE_XAUTHPAM),true)
XAUTH_USEPAM=1
endif
endif

FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8

# -O on Linux makes gcc coredump when compiling sha1.c
# -Wundef is nice but RHL5.2 compiler doesn't support it
CFLAGS = -g -Wall -W -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast \
	-Wcast-qual -Wmissing-declarations -Wwrite-strings \
	-Wstrict-prototypes # -Wundef

# where to find klips headers and Openswan headers
# and 2.6 kernel's <rtnetlink.h> and <xfrm.h>
HDRDIRS = -I${OPENSWANSRCDIR}/programs/pluto/linux26 -I${OPENSWANSRCDIR}/include -I$(OPENSWANSRCDIR)/lib/libcrypto -I$(KLIPSINC) 

# On non-LINUX systems, these one of these may be needed (see endian.h)
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=BIG_ENDIAN
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN

# -DKLIPS enables interface to Kernel LINUX IPsec code
# -DDEBUG enables debugging code, allowing for debugging output
#    (note that output must also be selected at runtime, so it is
#    reasonable to always define this)
# -DX509_VERSION is used to transfer the X.509 version number to Pluto
# -DPLUTO_SENDS_VENDORID enables pluto to send out a VendorID payload.
#    this can be used by remote nodes to work around faults (bugs),
#    but is most useful to humans who are debugging things.
# -DGCC_LINT uses gcc-specific declarations to improve compile-time
#    diagnostics.
# -DLEAK_DETECTIVE enables crude code to find memory allocation leaks.
# -DOLD_RESOLVER.  At some point, the resolver interface changed.
#    This macro enables Pluto support for the old interface.
#    It is automatically defined, based on the value of the <resolver.h>
#    macro __RES.  We don't know the correct threshold, so you may
#    find that you must manually define this.  If so, please inform
#    us so that we can refine the threshold.

# The following are best left undefined -- each can be overridden at runtime
# if need be.
# -DPORT=n sets the default UDP port for IKE messages (otherwise 500)
# -DSHARED_SECRETS_FILE=string overrides /etc/ipsec.secrets as the
#    default name of the file containing secrets used to authenticate other
#    IKE daemons.  In the Makefile, two levels of quoting are needed:
#    -DSHARED_SECRETS_FILE='"/etc/ipsec.secrets"'
# -DDEFAULT_CTLBASE=string overrides /var/run/pluto as default directory
#    and basename for pluto's lockfile (.pid) and control socket (.ctl).
#    Double quoting may be needed.


BINNAMEPLUTO = pluto
BINNAMEWHACK = whack
BINNAMEWHACKINIT = whackinit
BINNAMEADNS = _pluto_adns

ifeq ($(USE_LWRES),true)
LWRESDEF=-DUSE_LWRES
USE_ADNS=false
BINNAMEADNSIFNEEDED=
else
USE_ADNS=true
BINNAMEADNSIFNEEDED=$(BINNAMEADNS)
endif

IPSECPOLICY_DIST_SRCS=rcv_info.c
ifeq ($(USE_IPSECPOLICY),true)
IPSECPOLICY_SRCS=${IPSECPOLICY_DIST_SRCS}
IPSECPOLICY_DEFINES=-DIPSECPOLICY
IPSECPOLICY_LIBS=$(POLICYLIB)
IPSECPOLICY_OBJS=rcv_info.o
endif

ifeq ($(USE_VENDORID),true)
VENDORID=-DPLUTO_SENDS_VENDORID
endif

ifeq ($(USE_KEYRR),true)
KEYRR_DEFINES=-DUSE_KEYRR
endif

KERNEL26_DIST_SRCS=kernel_netlink.c kernel_netlink.h
ifeq ($(USE_KERNEL26),true)
KERNEL26_DEFS=-DKERNEL26_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES 
KERNEL26_SRCS=${KERNEL26_DIST_SRCS}
KERNEL26_OBJS=kernel_netlink.o
endif

# the files are defined here so that TAGS: can catch them.
#
X509_DIST_OBJS=ac.o asn1.o oid.o pem.o pgp.o pkcs.o x509.o certs.o md2.o ocsp.o x509keys.o
X509_DIST_SRCS=oid.txt oid.pl ${X509_DIST_OBJS:.o=.c}
X509_DIST_SRCS+=ac.h asn1.h certs.h fetch.h oid.h pem.h pgp.h pkcs.h x509.h
HAVE_THREADS_DIST_OBJS=fetch.o 
HAVE_THREADS_DIST_SRCS=${HAVE_THREADS_DIST_OBJS:.o=.c}
SMARTCARD_DIST_OBJS=smartcard.o
SMARTCARD_DIST_SRCS=smartcard.c smartcard.h 
X509_OBJS=${X509_DIST_OBJS}
X509_SRCS=${X509_DIST_SRCS}
X509_DEFS=-DX509 
X509_DEFS=-DX509_VERSION=\"${X509_VERSION}\"

# dynamic LDAP CRL fetching requires OpenLDAP library
ifeq ($(USE_LDAP),true)
X509_LIBS+= -lldap
ifdef LDAP_VERSION
X509_DEFS+= -DLDAP_VER=$(LDAP_VERSION)
endif
endif

ifeq ($(HAVE_THREADS),true)
HAVE_THREADS_DEFS=-DHAVE_THREADS
HAVE_THREADS_OBJS=${HAVE_THREADS_DIST_OBJS}
HAVE_THREADS_SRCS=${HAVE_THREADS_DIST_SRCS}
HAVE_THREADS_LIBS=-lpthread
endif

ifeq ($(USE_SMARTCARD),true)
# smartcard functions are compiled in whether or not we have -lopensc,
# but ifndef SMARTCARD, they are dummy functions.
SMARTCARD_DEFS=-DSMARTCARD
SMARTCARD_SRCS=${SMARTCARD_DIST_SRCS}
SMARTCARD_OBJS=${SMARTCARD_DIST_OBJS}
SMARTCARD_LIBS=-lopensc
endif

XAUTH_DIST_SRCS=xauth.c xauth.h
XAUTH_DIST_OBJS=xauth.o
ifeq ($(USE_XAUTH),true)
# This compile option activates xauth code and modecfg needed by xauth
XAUTH_DEFS=-DXAUTH -DMODECFG
XAUTH_OBJS=${XAUTH_DIST_OBJS}
XAUTH_SRCS=${XAUTH_DIST_SRCS}
# if we use pam for password checking then add it too
ifeq ($(USE_XAUTHPAM),true)
XAUTHPAM_DEFS=-DXAUTH_USEPAM
XAUTHPAM_LIBS=-lpam
endif
endif

AGGRESSIVE_DIST_OBJS=ikev1_aggr.o
AGGRESSIVE_DIST_SRCS=${AGGRESSIVE_DIST_OBJS:.o=.c}
ifeq ($(USE_AGGRESSIVE),true)
# This compile option activates xauth code and modecfg needed by xauth
AGGRESSIVE_DEFS=-DAGGRESSIVE
AGGRESSIVE_OBJS=${AGGRESSIVE_DIST_OBJS}
AGGRESSIVE_SRCS=${AGGRESSIVE_DIST_SRCS}
endif

ifeq ($(USE_NAT_TRAVERSAL),true)
NAT_DEFS=-DNAT_TRAVERSAL -DVIRTUAL_IP 
endif

ifeq ($(USE_NAT_TRAVERSAL_TRANSPORT_MODE),true)
NAT_DEFS+=-DI_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
endif

ifeq ($(USE_LIBCURL),true)
# This compile option activates dynamic URL fetching
# with libcurl in the source code
CURL_DEFS=-DLIBCURL
CURL_LIBS=-lcurl
endif

ifeq ($(USE_WEAKSTUFF),true)
WEAK_DEFS=-DUSE_VERYWEAK_DH1=1 #-DUSE_1DES
endif

ifeq ($(USE_EXTRACRYPTO),true)
EXTRA_CRYPTO_DEFS=-DUSE_TWOFISH -DUSE_BLOWFISH -DUSE_SERPENT -DUSE_SHA2
EXTRA_CRYPTO_SRCS=ike_alg_blowfish.c ike_alg_twofish.c ike_alg_serpent.c ike_alg_sha2.c 
EXTRA_CRYPTO_OBJS=ike_alg_blowfish.o ike_alg_twofish.o ike_alg_serpent.o ike_alg_sha2.o 
EXTRA_CRYPTO_LIBS=$(LIBBLOWFISH) $(LIBTWOFISH) $(LIBSERPENT) $(LIBSHA2) 
endif

OS=$(shell uname -s | tr 'A-Z' 'a-z')
SYSDEP_SRC=sysdep_${OS}.c
SYSDEP_OBJ=sysdep_${OS}.o

BUILDER=${shell echo ${USER}@`hostname` }
# End of configuration coping options.

DEFINES = $(EXTRA_DEFINES) \
	$(IPSECPOLICY_DEFINES) ${VENDORID} \
	$(KEYRR_DEFINES) \
	$(BYTE_ORDER) \
	$(LWRESDEF) \
	$(KERNEL26_DEFS) \
	$(X509_DEFS) \
	${EXTRA_CRYPTO_DEFS} \
	$(HAVE_THREADS_DEFS) \
	$(SMARTCARD_DEFS) \
	-DPLUTO \
	-DKLIPS \
        -DBUILDER=\"${BUILDER}\" \
	-DDEBUG \
	-DGCC_LINT \
	-DUSE_AES -DUSE_3DES \
	-DIKE_ALG -DKERNEL_ALG -DDB_CONTEXT \
	${AGGRESSIVE_DEFS} \
	${XAUTH_DEFS} ${XAUTHPAM_DEFS} \
	${NAT_DEFS} ${CURL_DEFS}\
	${WEAK_DEFS} \
	${HW_DEFS} \
	# -DLEAK_DETECTIVE

CPPFLAGS = $(HDRDIRS) $(DEFINES) \
	-DSHARED_SECRETS_FILE=\"${FINALCONFDIR}/ipsec.secrets\" \
	-DPOLICYGROUPSDIR=\"${FINALCONFDDIR}/policies\" \
	-DPERPEERLOGDIR=\"${FINALLOGDIR}/pluto/peer\"

ALLFLAGS = $(CPPFLAGS) $(CFLAGS)

# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
LIBSPLUTO =$(OBJSGCRYPT) $(LIBDESLITE) $(LIBAES) $(OPENSWANLIB) 
LIBSPLUTO+=$(IPSECPOLICY_LIBS) $(X509_LIBS) $(SMARTCARD_LIBS) 
LIBSPLUTO+=$(HAVE_THREADS_LIBS) ${XAUTHPAM_LIBS}
LIBSPLUTO+=${CURL_LIBS} 
LIBSPLUTO+=${EXTRA_CRYPTO_LIBS}
LIBSPLUTO+= -lgmp -lresolv # -lefence

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS=-L$(LD_LIBRARY_PATH)
endif

LIBSADNS = $(OPENSWANLIB)
LIBSADNS += -lresolv # -lefence

# Solaris needs -lsocket -lnsl
LIBSWHACK = whacklib.o ${OPENSWANLIB} 


RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

DISTMISC = CHANGES PLUTO-CONVENTIONS TODO ipsec.secrets Makefile routing.txt \
	 pluto.8 ipsec.secrets.5 .cvsignore

DISTGCRYPT = \
	gcryptfix.c gcryptfix.h \
	dsa.c dsa.h \
	elgamal.c elgamal.h \
	primegen.c \
	smallprime.c

DISTSRC = \
	connections.c connections.h \
	pending.c pending.h \
	foodgroups.c foodgroups.h \
	cookie.c cookie.h \
	pluto_constants.c \
	crypto.h crypto.c \
	db_ops.c \
	defs.h defs.c \
	demux.c demux.h \
	dnskey.c dnskey.h \
	dpd.c dpd.h \
	id.c id.h \
	ipsec_doi.c ipsec_doi.h ikev1_quick.c ikev1_continuations.h \
	kernel.c kernel.h \
	kernel_netlink.c kernel_netlink.h \
	kernel_pfkey.c kernel_pfkey.h \
	kernel_noklips.c kernel_noklips.h \
	ike_alg.c ike_alg.h ikeping.c \
	ike_alg_aes.c ike_alginit.c \
	rcv_whack.c rcv_whack.h \
	$(IPSECPOLICY_DIST_SRCS) \
	${EXTRA_CRYPTO_SRCS} \
	log.c log.h \
	plutomain.c plutoalg.c \
	md2.c md2.h \
	md5.c md5.h \
	ocsp.c ocsp.h \
	pluto_crypt.c crypt_utils.c pluto_crypt.h crypt_ke.c crypt_dh.c \
	lex.c lex.h \
	keys.c keys.h secrets.h \
	rnd.c rnd.h \
	server.c server.h \
	sha1.c sha1.h \
	${SMARTCARD_DIST_SRCS} \
	spdb.c spdb_struct.c spdb_print.c spdb.h \
	state.c state.h \
	stubs.c \
	${SYSDEP_SRC} \
	timer.c timer.h \
	$(DISTGCRYPT) \
	$(X509_DIST_SRCS) \
	$(HAVE_THREADS_DIST_SRCS) \
	vendor.c nat_traversal.c virtual.c \
	adns.c adns.h \
	whack.c whack.h whackinit.c whacklib.c\
	${XAUTH_DIST_SRCS} \
	${AGGRESSIVE_DIST_SRCS} 

DIST = $(DISTMISC) $(DISTSRC)


# start of support for DSS/DSA.  Not currently used.
# OBJSGCRYPT =  gcryptfix.o dsa.o elgamal.o primegen.o smallprime.o
OBJSGCRYPT =

OBJSLIBPLUTO = whacklib.o

OBJSPLUTO  = connections.o pending.o cookie.o crypto.o defs.o dpd.o
OBJSPLUTO += foodgroups.o log.o state.o plutomain.o plutoalg.o server.o
OBJSPLUTO += timer.o pluto_constants.o
OBJSPLUTO += id.o ipsec_doi.o ikev1_quick.o ikeping.o kernel.o 
OBJSPLUTO += $(KERNEL26_OBJS) 
OBJSPLUTO += kernel_pfkey.o kernel_noklips.o rcv_whack.o 
OBJSPLUTO += ${IPSECPOLICY_OBJS} demux.o lex.o keys.o dnskey.o
OBJSPLUTO += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o
OBJSPLUTO += rnd.o spdb.o spdb_struct.o spdb_print.o sha1.o md5.o 
OBJSPLUTO += vendor.o nat_traversal.o virtual.o 
OBJSPLUTO += ike_alg_aes.o ike_alginit.o
OBJSPLUTO += ${EXTRA_CRYPTO_OBJS}
OBJSPLUTO += ike_alg.o db_ops.o 
OBJSPLUTO += ${XAUTH_OBJS}
OBJSPLUTO += ${AGGRESSIVE_OBJS}
OBJSPLUTO += ${SMARTCARD_OBJS} ${X509_OBJS} ${HAVE_THREADS_OBJS}
OBJSPLUTO += ${OBJSLIBPLUTO}
OBJSPLUTO += ${SYSDEP_OBJ} stubs.o

OBJSADNS = adns.o

OBJSWHACK = whack.o
OBJSWHACKINIT = whackinit.o


all: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) #$(BINNAMEWHACKINIT) 
programs: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) #$(BINNAMEWHACKINIT)

oid.c: oid.txt oid.pl
	perl oid.pl

oid.h: oid.txt oid.pl
	perl oid.pl

install: all
	mkdir -p ${LIBEXECDIR} ${LIBDIR}
	mkdir -p -m 755 $(CONFDIR)/ipsec.d
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/cacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/aacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/ocspcerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/certs
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/crls
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/private
	mkdir -p -m 700 $(VARDIR)/run/pluto
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(BINNAMEWHACK) $(LIBEXECDIR)
	#$(INSTALL) $(INSTSUIDFLAGS) $(BINNAMEWHACKINIT) $(LIBEXECDIR)
	if $(USE_ADNS) ; then $(INSTALL) $(INSTBINFLAGS) $(BINNAMEADNS)  $(LIBEXECDIR) ; fi
	$(INSTALL) $(INSTMANFLAGS) ${srcdir}/pluto.8 $(PMANDIR)/ipsec_pluto.8
	sh ${OPENSWANSRCDIR}/packaging/utils/manlink pluto.8 | \
		while read from to ; \
		do \
			ln -s -f ipsec_$$from $(PMANDIR)/$$to; \
		done
	$(INSTALL) $(INSTMANFLAGS) ${srcdir}/ipsec.secrets.5 $(FMANDIR)
	sh ${OPENSWANSRCDIR}/packaging/utils/manlink ipsec.secrets.5 | \
		while read from to ; \
		do \
		 ln -s -f $$from $(FMANDIR)/$$to; \
		done

install_file_list:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)
	@if $(USE_ADNS) ; then echo $(LIBDIR)/$(BINNAMEADNS) ; fi
	@echo $(LIBEXECDIR)/$(BINNAMEWHACK)
	@echo $(PMANDIR)/ipsec_pluto.8
	@sh ${OPENSWANSRCDIR}/packaging/utils/manlink pluto.8 | \
		while read from to; \
		do\
			 echo $(PMANDIR)/$$to; \
		done
	@echo $(FMANDIR)/ipsec.secrets.5
	@sh ${OPENSWANSRCDIR}/packaging/utils/manlink ipsec.secrets.5 | \
		while read from to; \
		do \
			echo $(FMANDIR)/$$to; \
		done

alg_info_test: alg_info_test.o ike_alg.o constants.o defs.o log.o db_ops.o crypto.o $(LIBDESLITE) $(OPENSWANLIB)
	$(CC) -o $@ $^ $(LIBSPLUTO)

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS) $(OPENSWANLIB)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(USERLINK) $(OBJSPLUTO) $(LIBSPLUTO) 

$(BINNAMEADNS): $(OBJSADNS)
	$(CC) -o $(BINNAMEADNS) $(OBJSADNS) $(USERLINK) $(LIBSADNS)

$(BINNAMEWHACK): $(OBJSWHACK)
	$(CC) -o $(BINNAMEWHACK) $(OBJSWHACK) $(USERLINK) $(LIBSWHACK)

$(BINNAMEWHACKINIT): $(OBJSWHACKINIT)
	$(CC) -o $(BINNAMEWHACKINIT) $(OBJSWHACKINIT) $(USERLINK) $(LIBSWHACK)

distlist:
	@echo $(DIST)

# Exuberant Ctags doesn't work if LC_ALL is set to something other than C

CTAGSFLAGS = -N --format=1 # fishy options required for Exuberant Ctags

TAGSFILES=$(DISTSRC) $(LIBOPENSWANDIR)/*.[ch] ${OPENSWANSRCDIR}/include/*.h ${OPENSWANSRCDIR}/linux/include/*.h ${OPENSWANSRCDIR}/linux/include/openswan/*.h
tags:	$(TAGSFILES)
	LC_ALL=C ctags $(CTAGSFLAGS) ${TAGSFILES}

TAGS:	$(TAGSFILES)
	LC_ALL=C etags $(ETAGSFLAGS) ${TAGSFILES}

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

clean:
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(OBJSPLUTO) $(BINNAMEPLUTO) \
		$(OBJSWHACK) $(BINNAMEWHACK) \
		$(OBJSADNS) $(BINNAMEADNS)

check:
	echo no checks in lib right now.

checkprograms:

.c.o:
	$(CC) $(COPTS) $(ALLFLAGS) $(USERCOMPILE) -c $<

%.i: %.c
	$(CC) $(COPTS) $(ALLFLAGS) -E -o $@ $<


# Gather dependencies caused by explicit #includes within .c files
depend:
	@(ls $(DISTSRC) | grep '\.c' | xargs gcc -MM ${COPTS} ${ALLFLAGS} ) | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend

-include ${srcdir}/Makefile.depend

# DO NOT DELETE

