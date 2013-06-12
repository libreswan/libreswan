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

LIBRESWANSRCDIR?=$(shell cd ..; pwd)
include $(LIBRESWANSRCDIR)/Makefile.inc

srcdir?=${LIBRESWANSRCDIR}/testing/

SUBDIRS+=pluto 
#SUBDIRS=lib utils 
#SUBDIRS+=klips 
#SUBDIRS+=scripts packaging
#SUBDORS+=libvirt
#SUBDIRS+=kunit
# FIXUP: pfkey should NOT be commented out, but it needs debuging:
#SUBDIRS+=pfkey

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# programs

prerequisites cleanall distclean mostlyclean realclean check clean spotless install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		 ${MAKE} -C $$d srcdir=${srcdir}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ;\
	done; 

