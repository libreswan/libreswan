include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

INIT_D_FILE=ipsec.init
SYSCONFIGFILE=$(builddir)/sysconfig.pluto
SYSCONFIGDIR=$(DESTDIR)$(SYSCONFDIR)/sysconfig
SYSVINIT_DEFAULT_START?=

# Use dependencies to force the order.
#
# (Without this, since local-install-base depends local-base, rules
# like local-base and installinitfiles and checkenabled are allowed to
# run in parallel)

local-base: $(INIT_D_FILE) $(SYSCONFIGFILE)

local-install-base: installsysconfig checkenabled

installsysconfig: local-base
	mkdir -p $(SYSCONFIGDIR)
	if test ! -f $(SYSCONFIGDIR)/pluto ; then \
		$(INSTALL) $(INSTCONFFLAGS) $(SYSCONFIGFILE) $(SYSCONFIGDIR)/pluto ; \
	fi

checkenabled: install.init.d installsysconfig
	@count=0 ; \
	for dir in $(DESTDIR)/etc/rc?.d ; do \
		if test -f $$dir/S??ipsec.init ; then \
			count=1 ; \
		fi ; \
	done ; \
	if test $$count = 0 ; then \
		echo "************************** WARNING ***********************************" ; \
		echo "** The ipsec service is not enabled." ; \
		echo "** Enable it using 'chkconfig ipsec on' or another similar method." ; \
		echo "**********************************************************************" ; \
	fi

include $(top_srcdir)/mk/install.mk
include $(top_srcdir)/mk/install.init.d.mk
include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/rules.mk
