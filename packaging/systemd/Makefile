LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${LIBRESWANSRCDIR}/packaging/fedora/

SYSTEMDFILES=ipsec.service
SUBDIRS=
SYSTEMDDIR=$(DESTDIR)/lib/systemd/system

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

programs:     systemdfiles
systemdfiles: $(SYSTEMDFILES)
install:      programs doinstall

doinstall: programs
	@mkdir -p $(SYSTEMDDIR)
	@for i in $(SYSTEMDFILES) ; do \
		$(INSTALL) $$i $(SYSTEMDDIR);  \
	done
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
