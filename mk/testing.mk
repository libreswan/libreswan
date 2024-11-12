# Testing MAKE variables, for Libreswan
#
# Copyright (C) 2024 Andrew Cagney
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

# Sub directories such as testing/web and testing/kvm pull in this
# file so that they get consistent definitions based on the contents
# of Makefile.inc.local.

ifdef KVM_RUTDIR
 TESTING_RUTDIR = $(KVM_RUTDIR)
else
 TESTING_RUTDIR ?= $(abs_top_srcdir)
 KVM_RUTDIR = $(TESTING_RUTDIR)
endif

ifdef KVM_BENCHDIR
 TESTING_BENCHDIR = $(KVM_BENCHDIR)
else
 TESTING_BENCHDIR ?= $(abs_top_srcdir)
 KVM_BENCHDIR = $(TESTING_BENCHDIR)
endif

ifdef KVM_SOURCEDIR
 TESTING_SOURCEDIR = $(KVM_SOURCEDIR)
else
 TESTING_SOURCEDIR ?= $(TESTING_RUTDIR)
 KVM_SOURCEDIR = $(TESTING_SOURCEDIR)
endif

ifdef KVM_WEBDIR
 TESTING_WEBDIR = $(KVM_WEBDIR)
else
 TESTING_WEBDIR ?= $(abs_top_srcdir)/RESULTS
 KVM_WEBDIR = $(TESTING_WEBDIR)
endif

# This gets different values depending on where WEBDIR is.
#
# Not sure about the names, need to specify:
#
# - starting commit
# - ending commit
# - prefix name
# - suffix name

TESTING_HASH ?= $(shell git -C $(TESTING_RUTDIR) show --no-patch --format=%H HEAD)
TESTING_ABBREV_HASH = $(shell git -C $(TESTING_RUTDIR) show --no-patch --format="%h" $(TESTING_HASH))

ifdef WEB_BRANCH_NAME
 TESTING_BRANCH_NAME = $(WEB_BRANCH_NAME)
else
 TESTING_BRANCH_NAME ?= $(shell git -C $(TESTING_RUTDIR) describe --abbrev=0)
endif

ifdef WEB_BRANCH_TAG
 TESTING_BRANCH_TAG = $(WEB_BRANCH_TAG)
else
 TESTING_BRANCH_TAG ?= $(TESTING_BRANCH_NAME)
endif

TESTING_BRANCH_COUNT = $(shell git -C $(TESTING_RUTDIR) rev-list --count $(TESTING_BRANCH_TAG)..$(TESTING_HASH))

ifeq ($(TESTING_WEBDIR),$(abs_top_srcdir)/RESULTS)
  GIT_DESCRIPTION = $(shell git -C $(TESTING_RUTDIR) describe --long)
  GIT_BRANCH = $(shell $(top_srcdir)/testing/web/gime-git-branch.sh $(TESTING_RUTDIR))
  TESTING_RUNDIR ?= $(GIT_DESCRIPTION)-$(GIT_BRANCH)
else
  TESTING_RUNDIR = $(TESTING_BRANCH_NAME)-$(TESTING_BRANCH_COUNT)-g$(TESTING_ABBREV_HASH)
endif

TESTING_RESULTSDIR = $(TESTING_WEBDIR)/$(TESTING_RUNDIR)

# these kickstart web pages; should be merged into above

ifneq ($(wildcard $(TESTING_WEBDIR)),)
 # don't set to empty so that ifdef works
 WEB_ENABLED = true
endif

