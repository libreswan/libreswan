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
INCLUDES+=-I. -I${KLIPSSRCDIR} -I${KLIPSD}
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
	rm -f $(builddir)/*.o
	rm -f $(builddir)/*.a
	rm -f $(builddir)/*.c

list-local-base:
	@: never nothing to do

$(LIB): $(OBJS) | $(builddir)
	cd $(builddir) && $(AR) $(ARFLAGS) $(LIB) $(OBJS)

include $(top_srcdir)/mk/depend.mk
