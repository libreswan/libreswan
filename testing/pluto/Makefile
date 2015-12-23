# Libreswan testing makefile
#
# Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

ifndef top_srcdir
include ../../mk/dirs.mk
endif
include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/config.mk

UTILS=${LIBRESWANSRCDIR}/testing/utils

check: 	${LIBRESWANSRCDIR}/kvmsetup.sh
ifeq ($(UPDATEONLY),)
	$(MAKE) -C $(LIBRESWANSRCDIR) kvm-keys-up-to-date
endif
# skip rebuilding KVMs unless started with: make check UPDATE=1
ifneq ($(UPDATE)$(UPDATEONLY),)
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --compile --install --hostname east
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --install --hostname west
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --install --hostname road
	${LIBRESWANSRCDIR}/testing/utils/runkvm.py --reboot --install --hostname north
endif
ifeq ($(UPDATEONLY),)
	rm -rf */OUTPUT
	../utils/swantest
endif

install checkprograms programs:
	@true
