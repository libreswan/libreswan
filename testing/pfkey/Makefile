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

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
include $(LIBRESWANSRCDIR)/Makefile.inc
include ${SRCDIR}Makefile.unit-settings

SRCDIR?=$(shell pwd)/

SUBDIRS=eroute-01 spi-01 spigrp-01 tncfg-01

def:	check

# programs

cleanall distclean install programs checkprograms check clean install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		${MAKE} -C $$d SRCDIR=${SRCDIR}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ;\
	done;
