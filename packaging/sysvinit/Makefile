LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${LIBRESWANSRCDIR}/packaging/sysvinit/

INITDFILES=ipsec.init
SUBDIRS=
INITDDIR=$(CONFDIR)/init.d

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

programs:     initdfiles
initdfiles:   $(INITDFILES)
install:      programs doinstall

doinstall: programs
	@mkdir -p $(INITDDIR)
	@for i in $(INITDFILES) ; do \
		$(INSTALL) $$i $(INITDDIR);  \
	done
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
