LIBRESWANSRCDIR?=$(shell cd ..; pwd)
SRCDIR?=${LIBRESWANSRCDIR}/packaging/
SUBDIRS=

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

cleanall mostlyclean realclean install programs man config spotless:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) SRCDIR=${SRCDIR}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ) || exit 1;\
	done; \
