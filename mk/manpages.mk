# Manpage rules, for Libreswan.
#
# Copyright (C) 2015-2016, Andrew Cagney <cagney@gnu.org>
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

# NOTE: libreswan includes custom makefile configuration first, hence
# need a weak assign

XMLTO ?= xmlto

# $(MANDIR$(suffix $(MANPAGE))) will expand one of the below, roughly:
# 3 is libraries; 8 is for system programs; and 5 is for file formats.
MANDIR.3 ?= $(MANTREE)/man3
MANDIR.5 ?= $(MANTREE)/man5
MANDIR.8 ?= $(MANTREE)/man8

# List of the intermediate (transformed) man pages.  Don't let GNU
# make delete these.
TRANSFORMED_MANPAGES = $(addprefix $(builddir)/,$(addsuffix .tmp,$(MANPAGES)))
.PRECIOUS: $(TRANSFORMED_MANPAGES)

# Given the file MANPAGE.[0-9].{xml,tmp}, generate a list of
# <refname/> entries, including the section number.

refnames = $(shell $(top_srcdir)/packaging/utils/refnames.sh $(1))

# Man pages to build, since the list of generated man pages isn't
# predictable (see refnames.sh) use a fake target to mark that each
# page has been generated.

local-manpages: $(addprefix $(builddir)/,$(addsuffix .man,$(MANPAGES)))

local-install-manpages: local-manpages
	@set -eu $(foreach manpage,$(MANPAGES), \
		$(foreach refname,$(call refnames,$(builddir)/$(manpage).tmp), \
		$(foreach destdir,$(MANDIR$(suffix $(refname))), \
		; src=$(builddir)/$(refname) \
		; echo $$src '->' $(destdir) \
		; mkdir -p $(destdir) \
		; $(INSTALL) $(INSTMANFLAGS) $$src $(destdir))))

list-local-manpages: $(TRANSFORMED_MANPAGES)
	@set -eu $(foreach manpage,$(MANPAGES), \
		$(foreach refname,$(call refnames,$(builddir)/$(manpage).tmp), \
		; echo $(MANDIR$(suffix $(refname)))/$(refname)))

local-clean-manpages:
	rm -f $(builddir)/*.[1-8]
	rm -f $(builddir)/*.[1-8].tmp
	rm -f $(builddir)/*.[1-8].man

# Default rule for creating the TRANSFORMED_MANPAGES.
#
# Directories, such as programs/configs/, that generate the man page
# source, should provide a custom equivalent of this rule.

$(builddir)/%.tmp: $(srcdir)/%.xml | $(builddir)
	${TRANSFORM_VARIABLES} < $< > $@.tmp
	mv $@.tmp $@

# Default rule for creating the man pages from the intermediate
# (transormed) input.
#
# Note: XMLTO seems to fail even when it succeeds so ignore the exit
# status and instead explicitlay check for the expected output files.
#
# Use a dummy target since the generated man pages probably don't
# match the target name.

$(builddir)/%.man: $(builddir)/%.tmp
	: ignoring seemingly bogus $(XMLTO) exit status
	$(XMLTO) man $< -o $(builddir) || true
	test -z "" $(foreach refname,$(call refnames,$<), -a -r $(builddir)/$(refname))
	touch $@
