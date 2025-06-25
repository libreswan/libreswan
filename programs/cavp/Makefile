# cavp Makefile, for libreswan
#
# Copyright (C) 2017-2018 Andrew Cagney
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

include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

# Cryptographic Algorithm Validation Program (CAVP)
# see: http://csrc.nist.gov/groups/STM/cavp/index.html

PROGRAM = cavp

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE =

OBJS += cavp.o
OBJS += cavps.o
OBJS += cavp_print.o
OBJS += cavp_parser.o
OBJS += cavp_entry.o

ifeq ($(USE_IKEv1),true)
OBJS += test_ikev1.o
OBJS += test_ikev1_psk.o
OBJS += test_ikev1_dsa.o
USERLAND_CFLAGS += -DUSE_IKEv1
endif
OBJS += test_ikev2.o
OBJS += test_sha.o
OBJS += test_hmac.o
OBJS += test_gcm.o

OBJS += acvp.o

OBJS += $(LIBRESWANLIB)
OBJS += $(IPSECCONFLIB)
OBJS += $(LSWTOOLLIBS)

USERLAND_LDFLAGS += $(NSS_LDFLAGS)
USERLAND_LDFLAGS += $(NSPR_LDFLAGS)

default: local-check
.PHONY: default

ifeq ($(USE_IKEv1),true)
TESTCHECKS = test.acvp.ikev2.ok test.acvp.ikev1_dsa.ok test.acvp.ikev1_psk.ok
else
TESTCHECKS = test.acvp.ikev2.ok
endif
local-check: $(TESTCHECKS)

.PRECIOUS: %.fax
test.cavp.%.fax: | $(builddir)/
	echo $@ $*
	curl -o $(builddir)/$@.bz2 https://download.libreswan.org/cavs/$*.fax.bz2
	bunzip2 $(builddir)/$@.bz2

.PRECIOUS: %.out
test.cavp.%.out: test.cavp.%.fax $(PROGRAM)
	$(builddir)/cavp \
		$(builddir)/test.cavp.$*.fax \
		> $(builddir)/test.cavp.$*.tmp
	mv  $(builddir)/test.cavp.$*.tmp  $(builddir)/test.cavp.$*.out

test.cavp.%.ok: test.cavp.%.out test.cavp.%.fax
	diff -u $(builddir)/test.cavp.$*.fax $(builddir)/test.cavp.$*.out
	touch $(builddir)/$@

.PRECIOUS: %.out
test.acvp.%.out: test.acvp.%.run $(PROGRAM)
	CAVP=$(builddir)/cavp \
		$(srcdir)/test.acvp.$*.run \
		> $(builddir)/test.acvp.$*.tmp
	mv $(builddir)/test.acvp.$*.tmp $(builddir)/test.acvp.$*.out

test.acvp.%.ok: test.acvp.%.json test.acvp.%.out
	diff -u $(srcdir)/test.acvp.$*.json $(builddir)/test.acvp.$*.out
	touch $(builddir)/$@

clean: clean.cavp
clean.cavp:
	rm -f $(builddir)/*.ok
	rm -f $(builddir)/*.fax
	rm -f $(builddir)/*.fax.bz2
	rm -f $(builddir)/*.out
	rm -f $(builddir)/*.tmp

include $(top_srcdir)/mk/program.mk
