# Install magic, for Libreswan
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

# $(call install-directory, <DIRECTORY>[, <UMASK>])
install-directory = \
	if test ! -d $(strip $(1)) ; then \
		mkdir -p $(strip $(1)) ; \
		test -z "$(strip $(2))" || chmod $(strip $(2)) $(strip $(1)) ; \
	fi

# $(call install-file, <SRC>, <DST>, <FLAGS>)
install-file = \
	echo $(strip $(1)) '->' $(strip $(2)) ; \
	$(INSTALL) $(INSTCONFFLAGS) $(strip $(3)) $(strip $(1)) $(strip $(2))

# $(call install-missing-file, <SRC>, <DST>, <FLAGS>)
install-missing-file = \
	if [ ! -f $(strip $(2)) ]; then \
		$(call install-file, $(1), $(2), $(3)); \
	else \
		echo "WARNING: $(strip $(2)): skipping update, new version is in $(strip $(1))" 1>&2 ; \
	fi
