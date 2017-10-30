# cavp Makefile, for libreswan
#
# Copyright (C) 2017 Andrew Cagney
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

# Cryptographic Algorithm Validation Program (CAVP)
# see: http://csrc.nist.gov/groups/STM/cavp/index.html

PROGRAM = cavp

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE =

OBJS += cavp.o
OBJS += cavp_print.o
OBJS += cavp_ikev1.o
OBJS += cavp_ikev2.o
OBJS += cavp_sha.o
OBJS += cavp_hmac.o
OBJS += cavp_gcm.o

#
# XXX: For the moment build things by pulling in chunks of pluto.
# What, if anything, should be moved to libswan or another library?
#
CFLAGS += -I$(top_srcdir)/programs/pluto
PLUTOOBJS += $(patsubst %.c,%.o,$(notdir $(wildcard $(top_srcdir)/programs/pluto/ike_alg*.c)))
PLUTOOBJS += ike_info.o
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

default: check
.PHONY: check default
check: ikev2.cavp ikev1_dsa.cavp ikev1_psk.cavp

.PRECIOUS: %.fax
%.fax: | $(builddir)
	curl -o $(builddir)/$@.bz2 https://download.libreswan.org/cavs/$@.bz2
	bunzip2 $(builddir)/$@.bz2

.PRECIOUS: %.out
%.out: %.fax $(PROGRAM)
	$(builddir)/cavp \
		-fips \
		$(builddir)/$*.fax \
		> $(builddir)/$*.tmp
	mv  $(builddir)/$*.tmp  $(builddir)/$*.out

%.cavp: %.out
	diff -u $(builddir)/$*.fax $(builddir)/$*.out
	touch $(builddir)/$*.cavp

clean: clean.cavp
clean.cavp:
	rm -f $(builddir)/*.cavp
	rm -f $(builddir)/*.fax
	rm -f $(builddir)/*.fax.bz2
	rm -f $(builddir)/*.out
	rm -f $(builddir)/*.tmp

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
