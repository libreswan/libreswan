LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${LIBRESWANSRCDIR}/packaging/fedora/

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

%: ${srcdir}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver ${LIBRESWANSRCDIR}/Makefile.top
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
