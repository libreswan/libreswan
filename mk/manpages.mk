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

XMLTO ?= xmlto --searchpath $(XMLTO_SEARCHPATH)

XMLTO_SEARCHPATH ?= $(abs_srcdir):$(abs_top_srcdir)/mk

# $(MANDIR$(suffix $(MANPAGE))) will expand one of the below, roughly:
# 3 is libraries; 5 is file formats; 7 is overviews; 8 is system
# programs.
MANDIR.3 ?= $(MANDIR)/man3
MANDIR.5 ?= $(MANDIR)/man5
MANDIR.7 ?= $(MANDIR)/man7
MANDIR.8 ?= $(MANDIR)/man8

# Given the file MANPAGE.[0-9].{xml,tmp}, generate a list of
# <refname/> entries, including the section number.

refnames = $(shell $(top_srcdir)/packaging/utils/refnames.sh $(1))

# Man pages to build, since the list of generated man pages isn't
# predictable (see refnames.sh) use a fake target to mark that each
# page has been generated.

local-manpages: $(addprefix $(builddir)/, $(addsuffix .man, $(MANPAGES)))
local-html:     $(addprefix $(builddir)/, $(addsuffix .html, $(MANPAGES)))

local-install-manpages: local-manpages
	@set -eu $(foreach manpage,$(MANPAGES), \
		$(foreach refname,$(call refnames,$(srcdir)/$(manpage).xml), \
		$(foreach destdir,$(DESTDIR)$(MANDIR$(suffix $(refname))), \
		; echo '$(builddir)/$(refname)' '->' $(destdir) \
		; mkdir -p $(destdir) \
		; $(INSTALL) $(INSTMANFLAGS) '$(builddir)/$(refname)' '$(destdir)')))

list-local-manpages:
	@set -eu $(foreach manpage,$(MANPAGES), \
		$(foreach refname,$(call refnames,$(srcdir)/$(manpage).xml), \
		; echo $(DESTDIR)$(MANDIR$(suffix $(refname)))/$(refname)))

local-clean-manpages:
	rm -f $(builddir)/*.[1-8]
	rm -f $(builddir)/*.[1-8].tmp
	rm -f $(builddir)/*.[1-8].man
	rm -f $(builddir)/*.[1-8].html

# Default rule for creating the man pages.
#
# Danger: XMLTO will barf when run on 9p (it tries to update ownership
# and fails).  The test KVMs point OBJDIR at /var/tmp to avoid this
# problem.
#
# Use a dummy target since the generated man pages probably don't
# match the target name.

define transform-doc
	$(TRANSFORM_VARIABLES) -i $(1)

endef

$(builddir)/%.man: $(srcdir)/%.xml $(top_srcdir)/mk/entities.xml | $(builddir)
	$(XMLTO) $(XMLTO_FLAGS) man $< -o $(builddir)
	set -e $(foreach r, $(shell $(top_srcdir)/packaging/utils/refnames.sh $<), \
		; echo Transform: $(builddir)/$(r) ; $(TRANSFORM_VARIABLES) -i $(builddir)/$(r))
	touch $@

$(builddir)/%.html: $(srcdir)/%.xml $(top_srcdir)/mk/entities.xml | $(builddir)
	$(XMLTO) $(XMLTO_FLAGS) html-nochunks -m $(top_srcdir)/mk/man-html-link.xsl $< -o $(top_builddir)/html
	$(TRANSFORM_VARIABLES) -i $(top_builddir)/html/$*.html
	touch $@
