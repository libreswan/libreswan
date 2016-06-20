LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/systemd/

UPSTARTFILE=ipsec.conf
DEFAULTFILE=default.pluto
SUBDIRS=
UPSTARTDIR=$(SYSCONFDIR)/init
DEFAULTDIR=$(SYSCONFDIR)/default

include ${LIBRESWANSRCDIR}/Makefile.inc

programs:     upstartfiles defaultfiles
upstartfiles: $(UPSTARTFILE)
defaultfiles: $(DEFAULTFILE)
install:      programs doinstall
install-programs: doinstall

doinstall: programs installupstartconf installdefault

installupstartconf:
	@mkdir -p $(UPSTARTDIR)
	$(INSTALL) $(UPSTARTFILE) $(UPSTARTDIR);

installdefault:
	mkdir -p $(DEFAULTDIR)
	if test ! -f $(DEFAULTDIR)/pluto ; then \
		$(INSTALL) $(DEFAULTFILE) $(DEFAULTDIR)/pluto ; \
	fi

%: ${SRCDIR}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
