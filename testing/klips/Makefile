# FreeS/WAN subdir makefile
# Copyright (C) 1998-2001  Henry Spencer.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

LIBRESWANSRCDIR=$(shell cd ../..; pwd)
include $(LIBRESWANSRCDIR)/Makefile.inc

SUBDIRS=

.PHONY: results check def clean

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check:
	unset KLIPS_MODULE; ${SHELL} ./dotests.sh

checkbase:
	unset KLIPS_MODULE; ${SHELL} ./dotests.sh

checkmod:
	KLIPS_MODULE=-module ./dotests.sh

spotcheck:
	@. ${LIBRESWANSRCDIR}/umlsetup.sh; . ./setup.sh; . $${UTILS}/functions.sh; eval `sed -e '/^#/d' -e '/^$$/d' ${SRCDIR}TESTLIST | perl $${UTILS}/shuffle.pl 1`


checkcon:
	cat ${SRCDIR}TESTLIST | sed -e '/^#/d' -e '/^$$/d' | while read testtype name status; \
	do\
		echo Working on $$name; \
		(cd $$name && ../../utils/redocon.sh); \
	done	

results:
	. ./setup.sh; perl $$UTILS/regress-summarize-results.pl results

install install_file_list checkprograms programs:
	@true

clean:
	cat ${SRCDIR}TESTLIST | while read testtype name status; \
	do\
		rm -rf $$name/OUTPUT;\
	done

cleanall: clean

distclean: clean
