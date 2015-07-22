# Makefile stub to build SUBDIRS
#
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

default:
	@echo "Please read INSTALL before running make"
	@false
.PHONY: default

include $(top_srcdir)/mk/targets.mk

# These extra recursive-targets need to be migrated to targets.mk
# (an/or quietly dropped).  They are here until the top-level Makefile
# gets cleaned up.

SUBDIR_TARGETS = man config
ifneq ($(filter $(GLOBAL_TARGETS),$(SUBDIR_TARGETS)),)
$(error Extra targets in $(SUBDIR_TARGETS))
endif
.PHONY: $(SUBDIR_TARGETS)

$(filter-out $(BROKEN_TARGETS),$(SUBDIR_TARGETS) $(GLOBAL_TARGETS)):
	@set -eu ; \
	for d in $(SUBDIRS) ; do \
		$(MAKE) -C $$d $(basename $@) ; \
	done
