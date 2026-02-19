# Test programs that run on the GUEST, for libreswan
#
# Copyright (C) 2015-2022  Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

SUBDIRS += asn1check
SUBDIRS += authbycheck
SUBDIRS += dncheck
SUBDIRS += enumcheck
SUBDIRS += flagscheck
SUBDIRS += hunkcheck
SUBDIRS += ipcheck
SUBDIRS += jambufcheck
SUBDIRS += kernel
SUBDIRS += keyidcheck
SUBDIRS += timecheck
SUBDIRS += ttodatacheck
SUBDIRS += vendoridcheck

ifeq ($(USE_LABELED_IPSEC),true)
SUBDIRS += getpeercon_server
endif

include $(top_srcdir)/mk/targets.mk
