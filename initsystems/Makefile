LIBRESWANSRCDIR?=$(shell cd ..; pwd)
srcdir?=${LIBRESWANSRCDIR}/initsystems/
INITSYSTEM?=$(shell $(SHELL) $(LIBRESWANSRCDIR)/packaging/utils/lswan_detect.sh init)
SUBDIRS=${INITSYSTEM}

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.top

cleanall mostlyclean realclean install programs man config checkprograms spotless:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${srcdir}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ) || exit 1;\
	done; \
