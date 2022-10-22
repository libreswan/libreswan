# /etc/init.d install targets, for Libreswan
#
# Copyright (C) 2022 Andrew Cagney
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

# Note: GNU Make doesn't let you combine pattern targets (e.x.,
# kvm-install-%: kvm-reboot-%) with .PHONY.  Consequently, so that
# patterns can be used, any targets with dependencies are not marked
# as .PHONY.  Sigh!

# Note: for pattern targets, the value of % can be found in the make
# variable '$*' (why not $%!?!?!, because that was used for archives).
# It is used to extract the DOMAIN from targets like
# kvm-install-DOMAIN.

ifndef INIT_D_FILE
$(error need INIT_D_FILE defined)
endif

# assume include $(top_srcdir)/mk/install.mk

# Force dependency order so that base and install rules aren't run in
# parallel.

local-base: $(INIT_D_FILE)

.PHONY: install.init.d
local-install-base: install.init.d
install.init.d: $(INIT_D_FILE) local-base
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_INIT_D_DIR))
	@set -eu ; $(call install-file, $(INSTBINFLAGS), \
		$(builddir)/$(INIT_D_FILE), \
		$(DESTDIR)$(EXAMPLE_INIT_D_DIR)/$(INIT_D_FILE))
ifeq ($(INSTALL_INITSYSTEM),true)
	@set -eu ; $(call install-directory, $(DESTDIR)$(INIT_D_DIR))
	@set -eu ; $(call install-missing-file, $(INSTBINFLAGS), \
		$(DESTDIR)$(EXAMPLE_INIT_D_DIR)/$(INIT_D_FILE), \
		$(DESTDIR)$(INIT_D_DIR)/ipsec)
endif

list-local-base: list.init.d
.PHONY: list.init.d
list.init.d:
	@set -eu ; echo $(EXAMPLE_INIT_D_DIR)/$(INIT_D_FILE)
ifeq ($(INSTALL_INITSYSTEM),true)
	@set -eu ; echo $(INIT_D_DIR)/$(INIT_D_FILE)
endif
