ifndef top_srcdir
include ../../mk/dirs.mk
endif

UNITDIR=$(shell pkg-config systemd --variable=systemdsystemunitdir)
SYSTEMDFILE=ipsec.service
SYSTEMDDIR=$(DESTDIR)$(UNITDIR)

include $(top_srcdir)/Makefile.inc

# Use dependencies to force the order: LOCAL-BASE,
# INSTALLSYSTEMDSERVICE, OLDINITDCHECK, POSTCHECK.
#
# (Without this, since local-install-base depends local-base, rules
# like local-base and installsystemdservice are allowed to run in
# parallel)

local-base: $(builddir)/$(SYSTEMDFILE)

local-install-base: installsystemdservice oldinitdcheck postcheck

installsystemdservice: local-base | $(SYSTEMDDIR)
	$(INSTALL) $(INSTCONFFLAGS) $(builddir)/$(SYSTEMDFILE) $(SYSTEMDDIR)
	@if test $(SYSTEMDDIR) = $(UNITDIR) ; then \
		echo running: systemctl --system daemon-reload; \
		systemctl --system daemon-reload ; \
	fi
	@if test -f $(DESTDIR)/$(FINALLIBEXECDIR)/portexcludes; then \
		echo fixing port excludes ; \
		sed -Ei 's@^# (.*/portexcludes)$$@\1@' $(SYSTEMDDIR)/$(SYSTEMDFILE); \
	fi

$(SYSTEMDDIR):
	mkdir -p $(SYSTEMDDIR)

oldinitdcheck: installsystemdservice
	@if test -f $(DESTDIR)/etc/init.d/ipsec* ; then \
		if egrep -i '(openswan|libreswan)' $(DESTDIR)/etc/init.d/ipsec* > /dev/null 2>&1 ; then \
			echo "WARNING: removing older SYSV style init files" ; \
			echo "removing: " $(DESTDIR)/etc/init.d/ipsec* $(DESTDIR)/etc/rc*.d/[KS][0-9][0-9]ipsec* ; \
			rm -f $(DESTDIR)/etc/init.d/ipsec* $(DESTDIR)/etc/rc*.d/[KS][0-9][0-9]ipsec* ; \
		else \
			echo "************************** WARNING ***********************************" ; \
			echo "old " $(DESTDIR)/etc/init.d/ipsec* " files were found; these should be removed" ; \
			echo "**********************************************************************" ; \
		fi ; \
	fi

postcheck: installsystemdservice oldinitdcheck
	@if test -z "$(DESTDIR)" -a $(SYSTEMDDIR) = $(UNITDIR) -a $(shell systemctl is-enabled ipsec.service) = "disabled" ; then \
		echo "DESTDIR='$(DESTDIR)'" ; \
		echo "************************** WARNING ***********************************" ; \
		echo "The ipsec service is currently disabled. To enable this service issue:" ; \
		echo " systemctl enable ipsec.service" ; \
		echo "**********************************************************************" ; \
	fi ; \
	if test -z "$(DESTDIR)" -a $(shell systemctl is-active ipsec.service) = "disabled" ; then \
		echo "The ipsec service is currently disabled. To enable this service on boot issue:" ; \
		echo " systemctl enable ipsec.service" ; \
	fi ; \
	if test -z "$(DESTDIR)" -a $(shell systemctl is-active ipsec.service) = "active" ; then \
		echo "************************** WARNING ***********************************" ; \
		echo "The ipsec service is currently running. You need to restart the service using:" ; \
		echo " systemctl restart ipsec.service" ; \
		echo "**********************************************************************" ; \
	fi

# XXX: identical to program.mk?

$(builddir)/%: $(srcdir)/%.in $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	@echo  'IN' $< '->' $@
	$(TRANSFORM_VARIABLES) < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "$(PROGRAM).in" = $< ]; then chmod +x $@; fi

include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/builddir.mk
