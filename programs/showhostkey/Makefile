# Makefile for miscellaneous programs
# Copyright (C) 2002  Michael Richardson	<mcr@freeswan.org>
# Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#

PROGRAM=showhostkey

OBJS += $(PROGRAM).o
OBJS += $(LIBRESWANLIB)
OBJS += $(LSWTOOLLIBS)

USERLAND_LDFLAGS += $(NSS_UTIL_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_LDFLAGS)
USERLAND_LDFLAGS += $(NSPR_LDFLAGS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
