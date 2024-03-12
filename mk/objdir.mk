# Define OBJDIR, for Libreswan pathnames
#
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#
# OSDEP - the target's OS
#
# Below assumes a native build.  Cross compiling will need to override
# this.
#
# "uname" describes the the build system's kernel, and not the target
# system's operating environment (architecture, kernel, operating
# system version, glibc version, ...).
#
# An improvement might be:
#
#   $(CC) -dumpmachine
#
# but this assumes CC has already been set (currently CC can be set
# later, via Makefile.inc, by mk/defaults/$(OSDEP).mk.
#
# Trying to query the build environment with tricks like:
#
#   ( echo '#include <features.h>' ; echo 'major=__GLIBC__ ;
#   minor=__GLIBC_MINOR__') | gcc -E -
#
# have a similar result.

# OSDEP=linux,bsd,cygwin,darwin
ifeq ($(OSDEP),)
OSDEP:=$(shell uname -s | tr 'A-Z' 'a-z')
endif
export OSDEP

#
# OBJDIR - directory to store result
#
# The obsession with reproducible builds means that this variable
# can't contain anything that might identify the build system, such as
# the host name.
#
# Below assumes build directory is local.  Shared directory builds
# will need to override this (the test VMs, for instance, build into
# /var/tmp/OBJDIR).
#

ifndef OBJDIR
ARCH ?= $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/ -e 's/ //g')
# evaluate once
OBJDIR := OBJ.$(OSDEP).$(ARCH)
endif
export OBJDIR
