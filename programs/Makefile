# Makefile for the KLIPS interface utilities
#
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

ifndef top_srcdir
include ../mk/dirs.mk
endif
include $(top_srcdir)/Makefile.inc

SUBDIRS=

SUBDIRS+=proc pluto addconn
SUBDIRS+=configs _keycensor _plutorun _stackmanager
SUBDIRS+=_secretcensor _updown
SUBDIRS+=auto barf verify ipsec look newhostkey
SUBDIRS+=rsasigkey setup showhostkey
SUBDIRS+=readwriteconf
SUBDIRS+=_import_crl

ifeq ($(USE_KLIPS),true)
SUBDIRS+= _updown.klips
SUBDIRS+=spi eroute spigrp tncfg klipsdebug pf_key
endif
ifeq ($(USE_MAST),true)
SUBDIRS+= _updown.mast
endif
ifeq ($(USE_NETKEY),true)
SUBDIRS+= _updown.netkey
endif
ifeq ($(USE_BSDKAME),true)
SUBDIRS+=_realsetup.bsd _updown.bsdkame
endif

include $(top_srcdir)/mk/subdirs.mk
