LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${LIBRESWANSRCDIR}/initsystems/sysvinit/

INITDFILES=ipsec.init
SYSCONFIGFILES=sysconfig.pluto
SUBDIRS=
INITDDIR=$(CONFDIR)/init.d
SYSCONFIGDIR=$(CONFDIR)/sysconfig

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

programs:     initdfiles sysconfigfiles
initdfiles:   $(INITDFILES)
sysconfigfiles: $(SYSCONFIGFILES)
install:      programs doinstall

doinstall: programs installinitfiles installsysconfig checkenabled

installinitfiles:
	mkdir -p $(INITDDIR)
	@for i in $(INITDFILES) ; do \
		$(INSTALL) $$i $(INITDDIR);  \
	done

installsysconfig:
	mkdir -p $(SYSCONFIGDIR)
	if test ! -f $(SYSCONFIGDIR)/pluto ; then \
		$(INSTALL) sysconfig.pluto $(SYSCONFIGDIR)/pluto ; \
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
		echo "** Enable it using 'chkconfig ipsec.init on' or anothr similar method." ; \
		echo "**********************************************************************" ; \
	fi

%: ${srcdir}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver ${LIBRESWANSRCDIR}/Makefile.top
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
