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
# 3 is libraries; 5 is file formats; 7 is overviews; 8 is system
# programs.
MANDIR.3 ?= $(MANDIR)/man3
MANDIR.5 ?= $(MANDIR)/man5
MANDIR.7 ?= $(MANDIR)/man7
MANDIR.8 ?= $(MANDIR)/man8

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

local-manpages: $(addprefix $(builddir)/, $(addsuffix .man, $(MANPAGES)))
local-html: $(addprefix $(top_builddir)/html/, $(addsuffix .html, $(MANPAGES)))

local-install-manpages: local-manpages
	@set -eu $(foreach manpage,$(MANPAGES), \
		$(foreach refname,$(call refnames,$(builddir)/$(manpage).tmp), \
		$(foreach destdir,$(DESTDIR)$(MANDIR$(suffix $(refname))), \
		; echo '$(builddir)/$(refname)' '->' $(destdir) \
		; mkdir -p $(destdir) \
		; $(INSTALL) $(INSTMANFLAGS) '$(builddir)/$(refname)' '$(destdir)')))

list-local-manpages: $(TRANSFORMED_MANPAGES)
	@set -eu $(foreach manpage,$(MANPAGES), \
		$(foreach refname,$(call refnames,$(builddir)/$(manpage).tmp), \
		; echo $(DESTDIR)$(MANDIR$(suffix $(refname)))/$(refname)))

local-clean-manpages:
	rm -f $(builddir)/*.[1-8]
	rm -f $(builddir)/*.[1-8].tmp
	rm -f $(builddir)/*.[1-8].man

# Default rule for creating the TRANSFORMED_MANPAGES.
#
# Directories, such as configs/, that generate the man page
# source, should provide a custom equivalent of this rule.

$(builddir)/%.tmp: $(srcdir)/%.xml | $(builddir)
	${TRANSFORM_VARIABLES} < $< > $@.tmp
	mv $@.tmp $@

# Default rule for creating the man pages from the intermediate
# (transformed) input.
#
# Danger: XMLTO will barf run on 9p (it tries to update ownership and
# fails).  The test KVMs point OBJDIR at /var/tmp to avoid this
# problem.
#
# Use a dummy target since the generated man pages probably don't
# match the target name.
#
# OpenBSD (same xmlto as everyone else) generates file names
# containing spaces instead of underscores.  Hack around this.

$(builddir)/%.man: $(builddir)/%.tmp
	$(XMLTO) $(XMLTO_FLAGS) man $< -o $(builddir)
	set -e ; for r in $$($(top_srcdir)/packaging/utils/refnames.sh "$(builddir)/$*.tmp") ; do \
		o=$$(echo "$${r}" | tr '_' ' ') ; \
		if test "$${o}" != "$${r}" -a -r "$(builddir)/$${o}" ; then \
			mv -v "$(builddir)/$${o}" "$(builddir)/$${r}" ; \
		fi ; \
	done
	touch $@

$(top_builddir)/html/%.html: $(builddir)/%.tmp
	$(XMLTO) $(XMLTO_FLAGS) html-nochunks -m $(top_srcdir)/mk/man-html-link.xsl $< -o $(top_builddir)/html
