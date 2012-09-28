# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
srcdir?=${LIBRESWANSRCDIR}/programs/

include ${LIBRESWANSRCDIR}/Makefile.inc

SUBDIRS=

ifeq ($(USE_IPSECPOLICY),true)
SUBDIRS+=showpolicy
endif

SUBDIRS+=proc pluto addconn 
SUBDIRS+=_confread _include _keycensor _plutoload _plutorun
SUBDIRS+=_realsetup _secretcensor _updown 
SUBDIRS+=auto barf verify ipsec look newhostkey ranbits secrets initnss
SUBDIRS+=rsasigkey setup showdefaults showhostkey 
SUBDIRS+=ikeping examples policy

ifeq ($(USE_KLIPS),true)
SUBDIRS+= _startklips _updown.klips 
SUBDIRS+=spi eroute spigrp tncfg klipsdebug pf_key
endif
ifeq ($(USE_MAST),true)
SUBDIRS+= _updown.mast 
endif
ifeq ($(USE_NETKEY),true)
SUBDIRS+= _startnetkey _updown.netkey
endif
ifeq ($(USE_BSDKAME),true)
SUBDIRS+=_realsetup.bsd _updown.bsdkame
endif


def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# programs

cleanall distclean mostlyclean realclean install programs checkprograms clean spotless install_file_list:
ifeq ($(USE_XAUTHPAM),true)
	# install pam config file for XAUTH
	$(INSTALL) $(INSTCONFFLAGS) $(LIBRESWANSRCDIR)/pam.d/pluto /etc/pam.d/pluto || exit 1;
endif
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${srcdir}$$d/ LIBRESWANSRCDIR=$(LIBRESWANSRCDIR) $@ ) || exit 1;\
	done; \

check:
	@echo "info: all tests (check) are now in ../testing, doing nothing here."

