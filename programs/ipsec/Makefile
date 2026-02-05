# Makefile for miscellaneous programs
# Copyright (C) 2002  Michael Richardson	<mcr@freeswan.org>
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
# Copyright (C) 2023 Tuomo Soini <tis@foobar.fi>
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

PROGRAM=ipsec
PROGRAMDIR=$(DESTDIR)$(SBINDIR)
# Do not prefix $(PROGRAM) man page with "ipsec-"
MANPROGPREFIX=

PROGRAM_MANPAGE = # suppress default

MANPAGES += ipsec.8
MANPAGES += ipsec-briefconnectionstatus.8
MANPAGES += ipsec-briefstatus.8
MANPAGES += ipsec-certutil.8
MANPAGES += ipsec-checkconfig.8
MANPAGES += ipsec-checknflog.8
MANPAGES += ipsec-checknss.8
MANPAGES += ipsec-connectionstatus.8
MANPAGES += ipsec-crlutil.8
MANPAGES += ipsec-delete.8
MANPAGES += ipsec-down.8
MANPAGES += ipsec-fetchcrls.8
MANPAGES += ipsec-fipsstatus.8
MANPAGES += ipsec-globalstatus.8
MANPAGES += ipsec-import.8
MANPAGES += ipsec-initnss.8
MANPAGES += ipsec-listall.8
MANPAGES += ipsec-listcacerts.8
MANPAGES += ipsec-listcerts.8
MANPAGES += ipsec-listcrls.8
MANPAGES += ipsec-listen.8
MANPAGES += ipsec-listpubkeys.8
MANPAGES += ipsec-modutil.8
MANPAGES += ipsec-pk12util.8
MANPAGES += ipsec-purgeocsp.8
MANPAGES += ipsec-redirect.8
MANPAGES += ipsec-replace.8
MANPAGES += ipsec-rereadall.8
MANPAGES += ipsec-rereadcerts.8
MANPAGES += ipsec-rereadsecrets.8
MANPAGES += ipsec-restart.8
MANPAGES += ipsec-route.8
MANPAGES += ipsec-showstates.8
MANPAGES += ipsec-shuntstatus.8
MANPAGES += ipsec-start.8
MANPAGES += ipsec-status.8
MANPAGES += ipsec-stop.8
MANPAGES += ipsec-trafficstatus.8
MANPAGES += ipsec-unroute.8
MANPAGES += ipsec-up.8
MANPAGES += ipsec-vfychain.8

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
