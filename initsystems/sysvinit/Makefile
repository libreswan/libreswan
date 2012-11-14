# Makefile for miscelaneous programs
# Copyright (C) 2002  Michael Richardson	<mcr@freeswan.org>
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

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
include ${LIBRESWANSRCDIR}/Makefile.inc

# this dance is because setup has to get installed as /etc/rc.d/init.d/ipsec
# not as /etc/rc.d/init.d/setup.
PROGRAMDIR=$(RCDIR)
PROGRAM=setup
NOINSTALL=true
EXTRA8MAN=setup.8

include ${srcdir}../Makefile.program

# We have to install the setup program into the rc.d directories.
# the original program goes into /etc/rc.d/init.d, and a symlink goes
# into the $BINDIR.
#
# the priorities match those in setup's chkconfig line
doinstall:: $(PROGRAM) $(CONFFILES) $(EXTRA8MAN) $(EXTRA5MAN) $(EXTRA5PROC) $(LIBFILES) $(CONFDFILES)
	# remove any old vendor file installed previously
	@rm -f $(BINDIR)/setup
	# check the directories we need exist (ie., make install DESTDIR=/tmp/IPsec)
	@mkdir -p $(RCDIR) $(BINDIR)
	# install and link everything
	@$(INSTALL) $(INSTBINFLAGS) setup $(RCDIR)/ipsec
	@ln -s $(FINALRCDIR)/ipsec $(BINDIR)/setup

install_file_list::
	@echo $(RCDIR)/ipsec
	@echo $(BINDIR)/setup

cleanall::
	@rm -f setup

