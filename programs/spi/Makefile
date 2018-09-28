# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
# Copyright (C) 2008 Michael Richardson <mcr@sandelman.ca>
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

PROGRAM=spi

MANPAGES += ipsec_$(PROGRAM).5

OBJS += $(PROGRAM).o

#
# XXX: For the moment build things by pulling in chunks of pluto.
# What, if anything, should be moved to libswan or another library?
#
CFLAGS += -I$(top_srcdir)/programs/pluto
PLUTOOBJS += $(patsubst %.c,%.o,$(notdir $(wildcard $(top_srcdir)/programs/pluto/ike_alg*.c)))
PLUTOOBJS += crypt_symkey.o
PLUTOOBJS += crypt_hash.o
PLUTOOBJS += test_buffer.o
PLUTOOBJS += ikev1_prf.o
PLUTOOBJS += ikev2_prf.o
PLUTOOBJS += crypt_prf.o
PLUTOOBJS += crypt_dh.o
PLUTOOBJS += crypt_utils.o
# Need absolute path as 'make' (check dependencies) and 'ld' (do link)
# are run from different directories.
OBJS += $(addprefix $(abs_top_builddir)/programs/pluto/, $(PLUTOOBJS))
# $(PROGRAM): pluto-base
# .PHONY: pluto-base
# pluto-base:
#	$(MAKE) -C $(top_srcdir)/programs/pluto base

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWTOOLLIBS)

OBJS += $(LIBSERPENT)
OBJS += $(LIBTWOFISH)

LDFLAGS += $(NSS_LDFLAGS)
LDFLAGS += $(NSPR_LDFLAGS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
