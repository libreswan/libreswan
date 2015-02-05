# Given either top_srcdir or top_builddir define all the autoconf
# style directory variables
#
# Copyright (C) 2015 Andrew Cagney <andrew.cagney@yahoo.ca>
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

# Usage is either:
#
#   top_srcdir?=../..
#   include $(top_srcdir)/Makefile.dirs
#
# or (see the script makeshadowdirs):
#
#   top_builddir=../..
#   include $(top_builddir)/../Makefile.dirs
#
# Since $(buildir)/Makefile includes $(srcdir)/Makefile there is
# double include problem, hence the ifndef below.

# The target .makefile.dirs.print, which prints the variables, can
# be used for testing.  For builddir:
#
#   make OBJDIR=OBJ.linux top_buildir=../.. -f ../../../Makefile.dirs .makefile.dirs.print
#
# for srcdir:
#
#   make OBJDIR=OBJ.linux top_srcdir=../.. -f ../../Makefile.dirs .makefile.dirs.print
#

ifndef makefile.dirs.path

# Given a path to a higher directory (e.g., ../..) convert it to the
# path down from that directory.
#
# For instance, given "../.." ($(1) variable) and the current
# directory "/libreswan/OBJ.linux/foo/bar" return "/foo/bar"
makefile.dirs.path = $(subst $(abspath $(1)),,$(abspath .))

ifndef OBJDIR
$(error OBJDIR must be defined)
endif

ifndef top_builddir
ifndef top_srcdir
$(error one of top_srcdir and top_builddir must be defined)
endif
endif

ifdef top_builddir
ifdef top_srcdir
$(error one of top_srcdir and top_builddir must be defined)
endif
endif

ifdef top_builddir
ifeq ($(top_builddir),.)
# avoid ./..
top_srcdir=..
else
top_srcdir=$(top_builddir)/..
endif
builddir=.
srcdir=$(top_srcdir)$(call makefile.dirs.path,$(top_builddir))
else ifdef top_srcdir
ifeq ($(top_srcdir),.)
# avoid ./OBJDIR
top_builddir=$(OBJDIR)
else
top_builddir=$(top_srcdir)/$(OBJDIR)
endif
srcdir=.
builddir=$(top_builddir)$(makefile.dir.path $(top_srcdir))
endif

abs_top_srcdir=$(abspath $(top_srcdir))
abs_top_builddir=$(abspath $(top_builddir))
abs_srcdir=$(abspath $(srcdir))
abs_builddir=$(abspath $(builddir))

# Dot targets are never the default.
.PHONY: .makefile.dirs.print
.makefile.dirs.print:
	@echo srcdir=$(srcdir)
	@echo builddir=$(builddir)
	@echo abs_srcdir=$(abs_srcdir)
	@echo abs_builddir=$(abs_builddir)
	@echo top_srcdir=$(top_srcdir)
	@echo top_builddir=$(top_builddir)
	@echo abs_top_srcdir=$(abs_top_srcdir)
	@echo abs_top_builddir=$(abs_top_builddir)

endif
