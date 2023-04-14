# *time_t tests Makefile, for libreswan
#
# Copyright (C) 2019 Andrew Cagney
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

PROGRAM = _timecheck

OBJS += timecheck.o
OBJS += check_monotime.o
OBJS += check_realtime.o
OBJS += check_deltatime.o

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWTOOLLIBS)

# Add RT_LDFLAGS for glibc < 2.17
USERLAND_LDFLAGS += $(RT_LDFLAGS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif

local-check: $(PROGRAM)
	$(builddir)/$(PROGRAM)
