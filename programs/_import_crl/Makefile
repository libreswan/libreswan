# _import_crl Makefile
# Copyright (C) 2015 Matt Rogers
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

PROGRAM=_import_crl
PROGRAM_MANPAGE =

include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

OBJS += import_crl.o

ifeq ($(USE_LIBCURL),true)
OBJS += fetch_curl.o
endif
ifeq ($(USE_LDAP),true)
OBJS += fetch_ldap.o
endif

OBJS += $(LIBRESWANLIB)
OBJS += $(IPSECCONFLIB)
OBJS += $(LSWTOOLLIBS)
USERLAND_LDFLAGS += $(NSS_LDFLAGS)
USERLAND_LDFLAGS += $(NSPR_LDFLAGS)
USERLAND_LDFLAGS += $(LDAP_LDFLAGS)
USERLAND_LDFLAGS += $(CURL_LDFLAGS)

include $(top_srcdir)/mk/program.mk
