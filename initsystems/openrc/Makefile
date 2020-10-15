ifndef top_srcdir
include ../../mk/dirs.mk
endif

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/openrc/

INITDFILE=$(builddir)/ipsec.init
SUBDIRS=

include ${LIBRESWANSRCDIR}/Makefile.inc

# Use dependencies to force the order.
#
# (Without this, since local-install-base depends local-base, rules
# like local-base and installinitfiles and checkenabled are allowed to
# run in parallel)

local-base:     $(INITDFILE)
local-install-base: installinitfiles checkenabled

installinitfiles: local-base
	mkdir -p $(INITDDIR)
	$(INSTALL) $(INITDFILE) $(INITDDIR)/ipsec

checkenabled: installinitfiles
	@echo checkenabled not yet implemented

include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/rules.mk
