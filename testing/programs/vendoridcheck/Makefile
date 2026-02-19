# vendorid Makefile, for libreswan
#
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

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE =

PROGRAM = _vendoridcheck

OBJS += vendoridcheck.o

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWTOOLLIBS)

# BROKEN
USERLAND_LDFLAGS += $(NSS_UTIL_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_LDFLAGS)
USERLAND_LDFLAGS += $(NSPR_LDFLAGS)


ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif

local-check: $(PROGRAM)
	$(builddir)/$(PROGRAM)
