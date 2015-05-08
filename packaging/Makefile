LIBRESWANSRCDIR?=$(shell cd ..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/packaging/
SUBDIRS=

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

# XXX: Should switch this directory to using subdirs.mk
manpages install-manpages install-programs list list-manpages list-programs:

cleanall mostlyclean realclean install programs man config spotless:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) SRCDIR=${SRCDIR}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ) || exit 1;\
	done; \
