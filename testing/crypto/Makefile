# Openswan testing makefile
# Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
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
#
# RCSID $Id: Makefile,v 1.4 2004/12/18 18:13:45 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
export OPENSWANSRCDIR
include $(OPENSWANSRCDIR)/Makefile.inc

SUBDIRS=
UTILS=${OPENSWANSRCDIR}/testing/utils

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check: 	${OPENSWANSRCDIR}/umlsetup.sh
	source ${OPENSWANSRCDIR}/umlsetup.sh; source setup.sh; source ${UTILS}/functions.sh; source TESTLIST

install install_file_list checkprograms programs:
	@true

clean:
	grep -v '^#' TESTLIST | while read testtype name status; \
	do\
		rm -rf $$name/OUTPUT; \
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

