# FreeS/WAN testing makefile
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
#
# RCSID $Id: Makefile,v 1.5 2005/08/05 17:04:54 mcr Exp $

OPENSWANSRCDIR?=../../..
srcdir?=./
include $(OPENSWANSRCDIR)/Makefile.inc

SUBDIRS=
SRCDIR=${srcdir}
UTILS=${OPENSWANSRCDIR}/testing/utils

TESTS=$(shell awk '{print $$2;}' ${srcdir}TESTLIST)

all: ${TESTS}
	echo ${TESTS}

%: %.c OUTPUT.%.txt
	source ${UTILS}/functions.sh; libtest `basename $< .c`

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check:
	REGRESSRESULTS=$${REGRESSRESULTS-../results} ; source ${UTILS}/functions.sh; source ${srcdir}TESTLIST

install install_file_list checkprograms programs:
	@true

clean:
	cat ${srcdir}TESTLIST | while read testtype name status; \
	do\
		rm -rf `basename $$name .c`;\
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

#
# $Log: Makefile,v $
# Revision 1.5  2005/08/05 17:04:54  mcr
# 	adjustment of test cases to work with object directories.
#
# Revision 1.4  2005/05/12 03:09:33  mcr
# 	added spdbph1 test case.
#
# Revision 1.3  2005/03/13 18:58:27  mcr
# 	added skeyid calculation test.
#
# Revision 1.2  2005/03/13 00:28:52  mcr
# 	make sure to export *LIB variables.
#
# Revision 1.1  2004/10/16 22:54:21  mcr
# 	new test case for spdb.c clone/copy functions.
#
# Revision 1.4  2004/04/09 18:09:41  mcr
# Moved from testing/lib/libfreeswan/Makefile,v
#
# Revision 1.3  2004/04/03 19:44:51  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.2  2003/11/05 04:57:30  dhr
#
# set up a default REGRESSRESULTS for libfreeswan tests (like other kinds of tests)
#
# Revision 1.1  2002/06/08 17:41:22  mcr
# 	library test routines.
#
# 



