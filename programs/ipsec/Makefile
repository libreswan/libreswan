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
# Do not prefix $(PROGRAM) man page with "ipsec_"
MANPROGPREFIX=

MANPAGES += ipsec_add.8
MANPAGES += ipsec_briefstatus.8
MANPAGES += ipsec_certutil.8
MANPAGES += ipsec_checknflog.8
MANPAGES += ipsec_checknss.8
MANPAGES += ipsec_crlutil.8
MANPAGES += ipsec_delete.8
MANPAGES += ipsec_down.8
MANPAGES += ipsec_fetchcrls.8
MANPAGES += ipsec_fipsstatus.8
MANPAGES += ipsec_globalstatus.8
MANPAGES += ipsec_import.8
MANPAGES += ipsec_initnss.8
MANPAGES += ipsec_listall.8
MANPAGES += ipsec_listcacerts.8
MANPAGES += ipsec_listcrls.8
MANPAGES += ipsec_listen.8
MANPAGES += ipsec_listpubkeys.8
MANPAGES += ipsec_modutil.8
MANPAGES += ipsec_ondemand.8
MANPAGES += ipsec_pk12util.8
MANPAGES += ipsec_purgeocsp.8
MANPAGES += ipsec_redirect.8
MANPAGES += ipsec_replace.8
MANPAGES += ipsec_rereadall.8
MANPAGES += ipsec_rereadcerts.8
MANPAGES += ipsec_rereadsecrets.8
MANPAGES += ipsec_restart.8
MANPAGES += ipsec_route.8
MANPAGES += ipsec_showstates.8
MANPAGES += ipsec_shuntstatus.8
MANPAGES += ipsec_start.8
MANPAGES += ipsec_status.8
MANPAGES += ipsec_stop.8
MANPAGES += ipsec_trafficstatus.8
MANPAGES += ipsec_unroute.8
MANPAGES += ipsec_up.8
MANPAGES += ipsec_vfychain.8

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
