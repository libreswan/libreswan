# Default Makefile targets, for Libreswan
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

# Define targets only build stuff in the current directory.  These are
# the rules that build-directories need to define.
#
# Note: Recursive targets should depend directly on these, and should
# not depend on other recursive targets.  Unfortunately doing this is
# just slog; the good news is that it just has to be done once, here.

GLOBAL_TARGETS += all programs manpages
LOCAL_TARGETS += local-programs local-manpages
all: local-programs local-manpages
ifeq ($(filter programs,$(BROKEN_TARGETS)),)
programs: local-programs
else
programs:: local-programs
endif
manpages: local-manpages

GLOBAL_TARGETS += install install-programs install-manpages
LOCAL_TARGETS += install-local-programs install-local-manpages
ifeq ($(filter install,$(BROKEN_TARGETS)),)
install: install-local-programs install-local-manpages
else
install:: install-local-programs install-local-manpages
endif
ifeq ($(filter install-programs,$(BROKEN_TARGETS)),)
install-programs: install-local-programs
else
install-programs:: install-local-programs
endif
install-manpages: install-local-manpages

GLOBAL_TARGETS += clean clean-programs clean-manpages
LOCAL_TARGETS += clean-local-programs clean-local-manpages
ifeq ($(filter clean,$(BROKEN_TARGETS)),)
clean: clean-local-programs clean-local-manpages
else
clean:: clean-local-programs clean-local-manpages
endif
clean-programs: clean-local-programs
clean-manpages: clean-local-manpages

GLOBAL_TARGETS += list
LOCAL_TARGETS += list-local
list: list-local

.PHONY: $(LOCAL_TARGETS)
$(LOCAL_TARGETS):
