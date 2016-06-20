LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/docker/

INITDFILE=ipsec.init
SYSCONFIGFILE=sysconfig.pluto
SUBDIRS=
INITDDIR=$(RCDIR)
SYSCONFIGDIR=$(SYSCONFDIR)/sysconfig
SYSVINIT_DEFAULT_START?=

include ${LIBRESWANSRCDIR}/Makefile.inc

programs:     initdfiles sysconfigfiles
initdfiles:   $(INITDFILE)
sysconfigfiles: $(SYSCONFIGFILE)
install:      programs doinstall
install-programs: doinstall

doinstall: programs installinitfiles installsysconfig checkenabled

installinitfiles:
	mkdir -p $(INITDDIR)
	$(INSTALL) $(INITDFILE) $(INITDDIR)/ipsec

installsysconfig:
	mkdir -p $(SYSCONFIGDIR)
	if test ! -f $(SYSCONFIGDIR)/pluto ; then \
		$(INSTALL) $(INSTCONFFLAGS) $(SYSCONFIGFILE) $(SYSCONFIGDIR)/pluto ; \
	fi

checkenabled:
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

%: ${SRCDIR}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< | sed -e "s:@SYSVINIT_DEFAULT_START@:${SYSVINIT_DEFAULT_START}:g" > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
