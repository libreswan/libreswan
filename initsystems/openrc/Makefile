LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/initsystems/openrc/

INITDFILE=ipsec.init
SUBDIRS=
INITDDIR=$(RCDIR)

include ${LIBRESWANSRCDIR}/Makefile.inc

programs:     ipsec.init
initdfiles:   $(INITDFILE)
install:      programs doinstall
install-programs: doinstall

doinstall: programs installinitfiles checkenabled

installinitfiles:
	mkdir -p $(INITDDIR)
	$(INSTALL) $(INITDFILE) $(INITDDIR)/ipsec

checkenabled:
	@echo checkenabled not yet implemented

%: ${SRCDIR}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
