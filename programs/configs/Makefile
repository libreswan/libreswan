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

CONFFILES=ipsec.conf
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

$(builddir)/ipsec.conf.5.xml: $(xmlsources)
	@mkdir -p $(builddir)
	cat $(xmlsources) > $@

clean-local-manpages: clean-local-xml-manpages
.PHONY: clean-local-xml-manpages
clean-local-xml-manpages:
	rm -f $(builddir)/ipsec.conf.5.xml
