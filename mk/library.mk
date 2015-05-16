# Make life easy, just include everything that is needed.

ifndef top_srcdir
include $(dir $(lastword $(MAKEFILE_LIST)))dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk
include $(top_srcdir)/mk/targets.mk

KLIPSD=${LIBRESWANSRCDIR}/linux/include
KLIPSSRCDIR=${LIBRESWANSRCDIR}/linux/net/ipsec

LEX=flex
ifeq ($(USE_YACC),true)
BISON=yacc -b parser
else
BISON=bison
endif

VPATH+= ${KLIPSSRCDIR}
OSDEP?=$(shell uname -s | tr 'A-Z' 'a-z')

# Original flags
INCLUDES+=-I. -I${KLIPSSRCDIR} -I${KLIPSD} -I${LIBRESWANSRCDIR}
INCLUDES+=-I${LIBRESWANSRCDIR}/include 
# nss
INCLUDES+=${NSSFLAGS}

CFLAGS+=${PORTINCLUDE} ${INCLUDES} ${CROSSFLAGS}

CFLAGS+=-pthread

# XXX: hack until everything uses a consistent .c.o rule
CFLAGS+=$(USERLAND_CFLAGS)

ARFLAGS=crvs

.PHONY:	all install clean l t lt tar check checkprograms

SHOULDWERESTART=$(wildcard ${ONEFILE})
ifeq ($(SHOULDWERESTART),${ONEFILE})
all programs man config clean:
	set -e ; \
	cd ${LIBRESWANSRCDIR} && cd ${OBJDIRTOP}/lib/lib${LIBRARY} && ${MAKE} $@
else
all:	$(LIB) 
programs: $(LIB) 
clean:	cleanall
# XXX: Hack until build works from either directory
install-local-programs: $(LIB)
endif

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

cleanall::
	rm -rf ${OBJS} $(LIB)

MK_DEPEND_FILES = $(OBJS)
MK_DEPEND_CFLAGS = $(CFLAGS)
include $(top_srcdir)/mk/depend.mk
