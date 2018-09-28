# Makefile for init systems, for libreswan.
#
# Copyright (C) 2015, 2017 Andrew Cagney
# Copyright (C) 2015-2016 Tuomo Soini <tis@foobar.fi>
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
include ../mk/dirs.mk
endif

# this file uses ifeq, so need config early
include $(top_srcdir)/mk/config.mk

ifneq ($(INITSYSTEM),)
SUBDIRS += $(INITSYSTEM)
endif

include $(top_srcdir)/mk/subdirs.mk
