# hunk like tests, for libreswan
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

# Underscore programs are for internal use only.
PROGRAM = _hunkcheck

OBJS += hunkcheck.o

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWTOOLLIBS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif
