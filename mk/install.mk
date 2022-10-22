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
		echo mkdir $(if $(2), -m $(strip $(2))) -p $(strip $(1)) ; \
		     mkdir $(if $(2), -m $(strip $(2))) -p $(strip $(1)) ; \
	fi

# $(call install-file, <FLAGS>, <SRC>, <DST>)
install-file = \
	echo $(strip $(2)) '->' $(strip $(3)) ; \
	$(INSTALL) $(strip $(1)) $(strip $(2)) $(strip $(3))

# $(call install-missing-file, <FLAGS>, <SRC>, <DST>)
install-missing-file = \
	if test ! -f $(strip $(3)) ; then \
		$(call install-file, $(1), $(2), $(3)); \
	else \
		echo "WARNING: $(strip $(3)): skipping update, new version is in $(strip $(2))" 1>&2 ; \
	fi
