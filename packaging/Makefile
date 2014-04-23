LIBRESWANSRCDIR?=$(shell cd ..; pwd)
srcdir?=${LIBRESWANSRCDIR}/packaging/
SUBDIRS=

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

cleanall mostlyclean realclean install programs man config spotless:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${srcdir}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ) || exit 1;\
	done; \
