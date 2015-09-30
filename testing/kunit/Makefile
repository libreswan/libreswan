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

SUBDIRS=libkern rcv-01 rcv-02 xmit-01 saref-01

def:	check

# programs

include/libreswan.h:
	@mkdir -p include/libreswan
	@(cd ${LIBRESWANSRCDIR}/linux && find include -type d -print ) | while read dir; do mkdir -p $$dir; echo making $$dir; done
	@(cd ${LIBRESWANSRCDIR}/linux && find include -type f -name '*.h' -print ) | while read file; do ln -f -s ${KLIPS_TOP}/$$file $$file; echo making $$file; done

include/linux/madelinks: include/linux/files.txt
	@(cd include/linux && make links )

include/net/madelinks: include/net/files.txt
	@(cd include/net && make links )

include/asm/madelinks: include/asm/files.txt
	@(cd include/asm && make links )

check:	include/libreswan.h include/linux/madelinks include/net/madelinks include/asm/madelinks

cleanall distclean install programs checkprograms check clean install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) SRCDIR=${SRCDIR}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ) || exit 1;\
	done;
