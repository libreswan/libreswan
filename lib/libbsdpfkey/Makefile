OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

CFLAGS+=-DIPSEC_DEBUG -DIPSEC
CFLAGS+=-DINET6

SRCS=	pfkey.c pfkey_dump.c
SRCS+=	ipsec_strerror.c #policy_parse.y policy_token.l
#SRCS+=	ipsec_dump_policy.c ipsec_get_policylen.c
OBJS=${SRCS:.c=.o} 

CLEANFILES+=	y.tab.c y.tab.h

YFLAGS+=-d -p __libipsecyy
LFLAGS+=-P__libipsecyy

MAN=	ipsec_set_policy.3 ipsec_strerror.3
MLINKS+=ipsec_set_policy.3 ipsec_get_policylen.3 \
	ipsec_set_policy.3 ipsec_dump_policy.3

LIBRARY=bsdpfkey
LIB=libbsdpfkey.a
ONEFILE=pfkey.c

include ${srcdir}../Makefile.library
