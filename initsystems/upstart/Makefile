include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/systemd/

UPSTARTFILE=$(builddir)/ipsec.conf
DEFAULTFILE=$(builddir)/default.pluto
SUBDIRS=
UPSTARTDIR=$(DESTDIR)$(SYSCONFDIR)/init
DEFAULTDIR=$(DESTDIR)$(SYSCONFDIR)/default

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

include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/rules.mk
