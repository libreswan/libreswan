# Make life easy, just include everything that is needed.

ifndef top_srcdir
include $(dir $(lastword $(MAKEFILE_LIST)))dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk
include $(top_srcdir)/mk/targets.mk

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

# So that removing something from $(OBJS) triggers an archive build:
# depend on Makefile; and always build a new archive.  Could also
# depend the mk/* directory?

$(LIB): $(OBJS) $(srcdir)/Makefile | $(builddir)
	rm -f $(builddir)/$(LIB).tmp
	cd $(builddir) && $(AR) $(ARFLAGS) $(LIB).tmp $(OBJS)
	mv $(builddir)/$(LIB).tmp $(builddir)/$(LIB)

include $(top_srcdir)/mk/depend.mk
include $(top_srcdir)/mk/builddir.mk
