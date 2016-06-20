# Make life easy, just include everything that is needed.

ifndef top_srcdir
include $(dir $(lastword $(MAKEFILE_LIST)))dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk
include $(top_srcdir)/mk/targets.mk

KLIPSD=${LIBRESWANSRCDIR}/linux/include
KLIPSSRCDIR=${LIBRESWANSRCDIR}/linux/net/ipsec

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

local-base: $(LIB)

local-clean-base:
	rm -f $(foreach f,$(OBJS) $(LIB), $(builddir)/$(f))

list-local-base:
	@: never nothing to do

$(LIB): $(OBJS)
	cd $(builddir) ; $(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

MK_DEPEND_FILES = $(OBJS)
MK_DEPEND_CFLAGS = $(CFLAGS)
include $(top_srcdir)/mk/depend.mk
