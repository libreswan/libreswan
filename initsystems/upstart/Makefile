ifndef top_srcdir
include ../../mk/dirs.mk
endif

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/systemd/

UPSTARTFILE=$(builddir)/ipsec.conf
DEFAULTFILE=$(builddir)/default.pluto
SUBDIRS=
UPSTARTDIR=$(SYSCONFDIR)/init
DEFAULTDIR=$(SYSCONFDIR)/default

include ${LIBRESWANSRCDIR}/Makefile.inc

# Use dependencies to force the order.
#
# (Without this, since local-install-base depends local-base, rules
# like local-base and installinitfiles and checkenabled are allowed to
# run in parallel)

local-base: $(UPSTARTFILE) $(DEFAULTFILE)
local-install-base: installupstartconf installdefault

installupstartconf: local-base
	@mkdir -p $(UPSTARTDIR)
	$(INSTALL) $(UPSTARTFILE) $(UPSTARTDIR);

installdefault: local-base
	mkdir -p $(DEFAULTDIR)
	if test ! -f $(DEFAULTDIR)/pluto ; then \
		$(INSTALL) $(DEFAULTFILE) $(DEFAULTDIR)/pluto ; \
	fi

# XXX: identical to program.mk?

$(builddir)/%: $(srcdir)/%.in $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi

include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/builddir.mk
