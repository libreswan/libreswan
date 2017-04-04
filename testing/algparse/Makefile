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

#
# For the moment build things by pulling in chunks of pluto.  What, if
# anything, should be moved to libswan or another library.
#

VPATH += $(top_srcdir)/programs/pluto
CFLAGS += -I$(top_srcdir)/lib/libcrypto

OBJS += $(patsubst %.c,%.o,$(notdir $(wildcard $(top_srcdir)/programs/pluto/ike_alg*.c)))

OBJS += ike_info.o
OBJS += crypt_symkey.o
OBJS += crypt_hash.o
OBJS += test_buffer.o

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE =

PROGRAM = algparse
OBJS += $(PROGRAM).o

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWLOGLIBS)

LDFLAGS += $(LIBSERPENT)
LDFLAGS += $(LIBTWOFISH)
LDFLAGS += $(NSS_LDFLAGS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif

selfcheck: $(PROGRAM)
	$(builddir)/$(PROGRAM) | diff -u $(srcdir)/OUTPUT.$(PROGRAM).txt -
