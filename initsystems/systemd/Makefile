LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${LIBRESWANSRCDIR}/initsystems/systemd/
UNITDIR=$(shell pkg-config systemd --variable=systemdsystemunitdir)

SYSTEMDFILE=ipsec.service
SYSCONFIGFILE=sysconfig.pluto
SUBDIRS=
SYSTEMDDIR=$(DESTDIR)/${UNITDIR}
SYSCONFIGDIR=$(CONFDIR)/sysconfig

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

programs:     systemdfiles sysconfigfiles
systemdfiles: $(SYSTEMDFILE)
sysconfigfiles: $(SYSCONFIGFILE)
install:      programs doinstall postcheck

doinstall: programs installsystemdservice installsysconfig oldinitdcheck 

installsystemdservice:
	@mkdir -p $(SYSTEMDDIR)
	$(INSTALL) $(SYSTEMDFILE) $(SYSTEMDDIR)
	@if test $(SYSTEMDDIR) = ${UNITDIR} ; then \
		systemctl daemon-reload ; \
	fi

installsysconfig:
	mkdir -p $(SYSCONFIGDIR)
	@if test ! -f $(SYSCONFIGDIR)/pluto ; then \
		$(INSTALL) $(SYSCONFIGFILE) $(SYSCONFIGDIR)/pluto ; \
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
		echo " systemctl enable ipsec.servce" ; \
	fi ; \
	if test $(shell systemctl is-active ipsec.service) = "active" ; then \
		echo "************************** WARNING ***********************************" ; \
		echo "The ipsec service is currently running. You need to restart the service using:" ; \
		echo " systemctl restart ipsec.servce" ; \
		echo "**********************************************************************" ; \
	fi

%: ${srcdir}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver ${LIBRESWANSRCDIR}/Makefile.top
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
