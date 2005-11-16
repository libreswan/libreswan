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
# RCSID $Id: Makefile,v 1.6 2004/12/18 18:13:45 mcr Exp $

OPENSWANSRCDIR?=$(shell cd .. && pwd)
include $(OPENSWANSRCDIR)/Makefile.inc

SUBDIRS=

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check:
	sh ./dotests.sh

install install_file_list checkprograms programs:
	@true

clean:
	cat TESTLIST | while read testtype name status; \
	do\
		rm -rf $$name/OUTPUT;\
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

#
# $Log: Makefile,v $
# Revision 1.6  2004/12/18 18:13:45  mcr
# 	adjusted Makefiles so that ${OBJDIR} builds work.
#
# Revision 1.5  2004/04/03 19:44:51  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.4  2002/06/02 21:51:56  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.3  2002/05/06 19:17:50  mcr
# 	added install_file_list target to gather list of all files that
# 	would be installed by "make install" (for PR#65).
# 	manlink has new "-n" option to just print which files would be
# 	created rather than actually doing it.
#
# Revision 1.2  2002/05/05 23:29:14  mcr
# 	use stock testing Makefile
#
# 



