# Makefile for miscelaneous programs
# Copyright (C) 2002-2006  Michael Richardson	<mcr@xelerance.com>
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

# the man page source is generated
MANPAGES += $(builddir)/ipsec.conf.5
MANPAGES += ipsec.secrets.5

#different mode
ipsec.secrets.INSTFLAGS = --mode=0600

CONFFILES += ipsec.conf
CONFFILES += ipsec.secrets

EXCONFILES=ipsec.win2k.conf

CONFDFILES = v6neighbor-hole.conf
CONFDSUBDIR = policies
CONFDSUBDIRFILES = clear clear-or-private private-or-clear private block

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif

xmlsources := $(patsubst d.ipsec.conf/%,${srcdir}/d.ipsec.conf/%,$(shell cat ${srcdir}/d.ipsec.conf/order.txt))

$(builddir)/ipsec.conf.5.xml: $(xmlsources) | $(builddir)
	cat $(xmlsources) > $@

local-clean-manpages: local-clean-xml-manpages
.PHONY: clean-local-xml-manpages
local-clean-xml-manpages:
	rm -f $(builddir)/ipsec.conf.5.xml
