# Test programs that run on the GUEST, for libreswan
#
# Copyright (C) 2015-2019,2021 Andrew Cagney <cagney@gnu.org>
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

ifndef top_srcdir
include ../../mk/dirs.mk
endif
include $(top_srcdir)/mk/config.mk

SUBDIRS += enumcheck
SUBDIRS += ipcheck
SUBDIRS += jambufcheck
SUBDIRS += timecheck
SUBDIRS += hunkcheck
SUBDIRS += dncheck
SUBDIRS += keyidcheck
ifeq ($(USE_LABELED_IPSEC),true)
SUBDIRS += getpeercon_server
endif

include $(top_srcdir)/mk/targets.mk
