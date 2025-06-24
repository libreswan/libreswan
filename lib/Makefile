# Makefile for the interface utilities
#
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

include ../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

SUBDIRS += libswan
SUBDIRS += liblswtool
ifeq ($(USE_SYSTEMD_WATCHDOG),true)
SUBDIRS += liblswsd
endif

include $(top_srcdir)/mk/targets.mk
