# algparse Makefile, for libreswan
#
# Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE =

PROGRAM = algparse
OBJS += $(PROGRAM).o

#
# XXX: For the moment build things by pulling in chunks of pluto.
# What, if anything, should be moved to libswan or another library?
#
PLUTOOBJS += $(patsubst %.c,%.o,$(notdir $(wildcard $(top_srcdir)/programs/pluto/ike_alg*.c)))
PLUTOOBJS += ike_info.o
PLUTOOBJS += crypt_symkey.o
PLUTOOBJS += crypt_hash.o
PLUTOOBJS += test_buffer.o
OBJS += $(addprefix $(top_builddir)/programs/pluto/, $(PLUTOOBJS))
# $(PROGRAM): pluto-base
# .PHONY: pluto-base
# pluto-base:
#	$(MAKE) -C $(top_srcdir)/programs/pluto base

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWLOGLIBS)
OBJS += $(LIBSERPENT)
OBJS += $(LIBTWOFISH)

LDFLAGS += $(NSS_LDFLAGS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif

selfcheck: $(PROGRAM)
	$(builddir)/$(PROGRAM) -v | diff -u $(top_srcdir)/testing/pluto/basic-pluto-00/OUTPUT.$(PROGRAM).txt -
