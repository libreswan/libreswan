LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/systemd/
UNITDIR=$(shell pkg-config systemd --variable=systemdsystemunitdir)

SYSTEMDFILE=ipsec.service
SUBDIRS=
ifeq ($(DESTDIR),)
SYSTEMDDIR=${UNITDIR}
else
SYSTEMDDIR=$(DESTDIR)/${UNITDIR}
endif

include ${LIBRESWANSRCDIR}/Makefile.inc

programs:     systemdfiles
systemdfiles: $(SYSTEMDFILE)
install:      programs doinstall postcheck
install-programs: doinstall postcheck

doinstall: programs installsystemdservice oldinitdcheck

installsystemdservice:
	@mkdir -p $(SYSTEMDDIR)
	$(INSTALL) $(INSTCONFFLAGS) $(SYSTEMDFILE) $(SYSTEMDDIR)
	@if test $(SYSTEMDDIR) = ${UNITDIR} ; then \
		systemctl --system daemon-reload ; \
	fi

oldinitdcheck:
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
postcheck:
	@if test $(SYSTEMDDIR) = ${UNITDIR} -a $(shell systemctl is-enabled ipsec.service) = "disabled" ; then \
		echo "************************** WARNING ***********************************" ; \
		echo "The ipsec service is currently disabled. To enable this service issue:" ; \
		echo " systemctl enable ipsec.service" ; \
		echo "**********************************************************************" ; \
	fi ; \
	if test $(shell systemctl is-active ipsec.service) = "disabled" ; then \
		echo "The ipsec service is currently disabled. To enable this service on boot issue:" ; \
		echo " systemctl enable ipsec.service" ; \
	fi ; \
	if test $(shell systemctl is-active ipsec.service) = "active" ; then \
		echo "************************** WARNING ***********************************" ; \
		echo "The ipsec service is currently running. You need to restart the service using:" ; \
		echo " systemctl restart ipsec.service" ; \
		echo "**********************************************************************" ; \
	fi

%: ${SRCDIR}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
