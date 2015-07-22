# Makefile for pluto/userspace crypto libraries
#
# Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
include ../../mk/dirs.mk
endif

include $(top_srcdir)/Makefile.inc

# needs ifdefs for USE_MD5, etc
SUBDIRS=libmd5 libsha1 libsha2 libaes_xcbc

ifeq ($(USE_EXTRACRYPTO),true)
SUBDIRS+=libtwofish libserpent
endif

include $(top_srcdir)/mk/subdirs.mk
