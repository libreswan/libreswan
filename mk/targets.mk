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
ifeq ($(filter all,$(BROKEN_TARGETS)),)
all: local-programs local-manpages
else
all:: local-programs local-manpages
endif
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

# The install_file_list target is special; the command:
#
#    $ make install_file_list > file-list
#
# must contain nothing but the list of installed files printed by the
# list-local-programs et.al. sub-targets.  Consequently:
#
# - to stop "Nothing to be done" messages, the target is never empty
#
# - to stop make's directory messages, --no-print-directory is
#   specified
install_file_list:
	@set -eu ; $(foreach dir,$(SUBDIRS), \
		echo $(PWD)/$(dir): 1>&2 ; \
		$(MAKE) -C $(dir) --no-print-directory $@ ; \
	)
.PHONY: install_file_list
install_file_list:  list-local-manpages list-local-programs
GLOBAL_TARGETS += list-manpages list-programs
LOCAL_TARGETS += list-local-manpages list-local-programs
list-manpages: list-local-manpages
list-programs: list-local-programs

# Global targets defined above
.PHONY: $(GLOBAL_TARGETS)

# Force default local target definition
.PHONY: $(LOCAL_TARGETS)
$(LOCAL_TARGETS):
