include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

UNITFILE=ipsec.service
TMPFILESCONFIG=libreswan.conf

# Use dependencies to force the order: LOCAL-BASE,
# INSTALLSYSTEMDSERVICE, OLDINITDCHECK, POSTCHECK.
#
# (Without this, since local-install-base depends local-base, rules
# like local-base and installsystemdservice are allowed to run in
# parallel)

BUILD = $(builddir)/$(UNITFILE) $(builddir)/$(TMPFILESCONFIG)
local-base: $(BUILD)
local-clean:
	rm -f $(BUILD)

ifeq ($(INSTALL_INITSYSTEM),true)
local-install-base: installsystemdservice oldinitdcheck postcheck
endif

installtmpfilesconfig: local-base | $(TMPFILESDIR)
	$(INSTALL) $(INSTCONFFLAGS) $(builddir)/$(TMPFILESCONFIG) $(TMPFILESDIR)
	@if test $(TMPFILESDIR) = $(SYSTEMTMPFILESDIR) ; then \
		echo running: systemd-tmpfiles --create $(TMPFILESDIR)/$(TMPFILESCONFIG); \
		systemd-tmpfiles --create $(TMPFILESDIR)/$(TMPFILESCONFIG); \
	fi

installsystemdservice: local-base | $(DESTDIR)$(SYSTEMUNITDIR)
	$(INSTALL) $(INSTCONFFLAGS) $(builddir)/$(UNITFILE) $(DESTDIR)$(SYSTEMUNITDIR)
	@if test $(DESTDIR)$(SYSTEMUNITDIR) = $(SYSTEMUNITDIR) ; then \
		echo running: systemctl --system daemon-reload; \
		systemctl --system daemon-reload || echo "failed restart" ; \
	fi
	@if test -f $(DESTDIR)/$(LIBEXECDIR)/portexcludes; then \
		echo fixing port excludes ; \
		sed -Ei 's@^# (.*/portexcludes)$$@\1@' $(DESTDIR)$(SYSTEMUNITDIR)/$(UNITFILE); \
	fi

$(DESTDIR)$(SYSTEMUNITDIR):
	mkdir -p $(DESTDIR)$(SYSTEMUNITDIR)

$(TMPFILESDIR):
	mkdir -p $(TMPFILESDIR)

oldinitdcheck: installsystemdservice
	@if test -f $(DESTDIR)/etc/init.d/ipsec* ; then \
		if grep -E -i '(openswan|libreswan)' $(DESTDIR)/etc/init.d/ipsec* > /dev/null 2>&1 ; then \
			echo "WARNING: removing older SYSV style init files" ; \
			echo "removing: " $(DESTDIR)/etc/init.d/ipsec* $(DESTDIR)/etc/rc*.d/[KS][0-9][0-9]ipsec* ; \
			rm -f $(DESTDIR)/etc/init.d/ipsec* $(DESTDIR)/etc/rc*.d/[KS][0-9][0-9]ipsec* ; \
		else \
			echo "************************** WARNING ***********************************" ; \
			echo "old " $(DESTDIR)/etc/init.d/ipsec* " files were found; these should be removed" ; \
			echo "**********************************************************************" ; \
		fi ; \
	fi

postcheck: installsystemdservice installtmpfilesconfig oldinitdcheck
	@if test -z "$(DESTDIR)" -a $(DESTDIR)$(SYSTEMUNITDIR) = $(SYSTEMUNITDIR) -a $(shell systemctl is-enabled ipsec.service) = "disabled" ; then \
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

include ${top_srcdir}/mk/targets.mk
include ${top_srcdir}/mk/rules.mk
