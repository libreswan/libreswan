# Makefile for init systems, for libreswan.
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
# Copyright (C) 2015 Tuomo Soini <tis@foobar.fi>
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

# Note: this variable gets passed in, as in "make INITSYSTEM=systemd"
INITSYSTEM ?= $(shell $(SHELL) $(top_srcdir)/packaging/utils/lswan_detect.sh init)

# XXX: Switch directory hack
config:
	$(MAKE) -C $(builddir)/$(INITSYSTEM) $@
# XXX: Both switch directory and change the target.
local-base:
	$(MAKE) -C $(builddir)/$(INITSYSTEM) programs
install-local-base:
	$(MAKE) -C $(builddir)/$(INITSYSTEM) install
local-clean:
	$(MAKE) -C $(builddir)/$(INITSYSTEM) cleanall

# Note: since this cherry-picks the sub-directory to "build" this
# isn't really a mk/subdirs.mk candidate.
ifndef top_srcdir
include ../mk/dirs.mk
endif
include $(top_srcdir)/mk/targets.mk
