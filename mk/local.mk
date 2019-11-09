# Wrapper around local make file, for Libreswan.
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

# Currently both mk/dirs.mk and Makefile.inc need to see the local
# definitions in Makefile.inc.local but Makefile.inc can't (yet)
# assume dirs.mk has been included.  This wrapper prevents multiple
# includes.

# Why can't mk/dirs.mk include Makefile.inc or Makefile.inc include
# mk/dirs?
#
# The problem is circular.  Makefile.inc uses variables like
# LIBRESWANSRCDIR but at the point where Makefile.inc.local should be
# included by mk/dirs.mk (very early as it might set OBJDIR),
# mk/dirs.mk hasn't yet had a chance to define them.

# Only include a local make file once.

ifndef local.mk
local.mk = true

# try to include
ifdef top_srcdir
# mk/dirs.mk case
-include $(top_srcdir)/Makefile.inc.local
else
# Makefile.inc case, when mk/dirs.mk hasn't been included
-include $(LIBRESWANSRCDIR)/Makefile.inc.local
endif
endif
