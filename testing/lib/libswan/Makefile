# libreswan testing makefile
# Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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

SHELL=/bin/bash
export SHELL

LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
include $(LIBRESWANSRCDIR)/Makefile.inc

SUBDIRS=
UTILS=${LIBRESWANSRCDIR}/testing/utils

def:	check

check:
	${SHELL} -c "unset module; export LIBRESWANLIB=${LIBRESWANLIB} REGRESSRESULTS=$${REGRESSRESULTS-../results} ; . ${UTILS}/functions.sh; . ./TESTLIST"

one:
	${SHELL} -c "unset module; export LIBRESWANLIB=${LIBRESWANLIB} REGRESSRESULTS=$${REGRESSRESULTS-../results} ; . ${UTILS}/functions.sh; eval `grep ${TEST} TESTLIST`"

install install_file_list checkprograms programs:
	@true

clean:
	cat TESTLIST | while read testtype name status; \
	do\
		rm -rf `basename $$name .c`;\
	done

cleanall: clean
