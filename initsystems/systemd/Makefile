LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${LIBRESWANSRCDIR}/initsystems/systemd/

SYSTEMDFILES=ipsec.service
SYSCONFIGFILES=sysconfig.pluto
SUBDIRS=
SYSTEMDDIR=$(DESTDIR)/lib/systemd/system
SYSCONFIGDIR=$(CONFDIR)/sysconfig

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

programs:     systemdfiles sysconfigfiles
systemdfiles: $(SYSTEMDFILES)
sysconfigfiles: $(SYSCONFIGFILES)
install:      programs doinstall

doinstall: programs installsystemdservice installsysconfig oldinitdcheck

installsystemdservice:
	@mkdir -p $(SYSTEMDDIR)
	@for i in $(SYSTEMDFILES) ; do \
		$(INSTALL) $$i $(SYSTEMDDIR);  \
	done

installsysconfig:
	mkdir -p $(SYSCONFIGDIR)
	if test ! -f $(SYSCONFIGDIR)/pluto ; then \
		$(INSTALL) sysconfig.pluto $(SYSCONFIGDIR)/pluto ; \
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

%: ${srcdir}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver ${LIBRESWANSRCDIR}/Makefile.top
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
