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


%: ${srcdir}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver ${LIBRESWANSRCDIR}/Makefile.top
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi
