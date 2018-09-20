ifndef top_srcdir
include ../../mk/dirs.mk
endif

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/openrc/

INITDFILE=$(builddir)/ipsec.init
SUBDIRS=
INITDDIR=$(RCDIR)

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

# XXX: identical to program.mk?

$(builddir)/%: $(srcdir)/%.in $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi

include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/builddir.mk
