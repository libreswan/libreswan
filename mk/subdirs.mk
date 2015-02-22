# Makefile stub to build SUBDIRS
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

TARGETS = cleanall distclean mostlyclean realclean install man config programs checkprograms check clean spotless install_file_list
.PHONY: $(TARGETS)

default:
	@echo "Please read INSTALL before running make"
	@false
.PHONY: default

# Give each target a subdirs target so that there is something to
# depend on should there be some sort of ordering problem.  (better
# handled by not using recursive make).

SUBDIR_TARGETS = $(patsubst %,%.subdirs,$(TARGETS))
.PHONY: $(SUBDIR_TARGETS)
# Need to do this explicitly, make ignores implict targets here.
cleanall: cleanall.subdirs
distclean: distclean.subdirs
mostlyclean: mostlyclean.subdirs
realclean: realclean.subdirs
install: install.subdirs
man: man.subdirs
config: config.subdirs
programs: programs.subdirs
checkprograms: checkprograms.subdirs
check: check.subdirs
clean: clean.subdirs
spotless: spotless.subdirs
install_file_list: install_file_list.subdirs
# add more here

# generate $(TARGET) variable name, where TARGET is the current
# target.  Uses $@ so only works within the target rule below.
mk.subdirs.target = $(shell echo $(basename $@) | tr '[a-z]' '[A-Z]')

# Decend into each of $(SUBDIRS) and run the target.  Use standard
# backward filter trick to skip directories also found in
# $(BROKEN_$(TARGET)_SUBDIRS)
$(SUBDIR_TARGETS):
	@set -eu ; \
	subdirs="$(SUBDIRS)" ; \
	echo "subdirs=$$subdirs" ; \
	broken="$(strip $(BROKEN_$(mk.subdirs.target)_SUBDIRS))" ; \
	echo "broken=$$broken" ; \
	for d in $$subdirs ; do \
		case " $$broken " in \
		*" $$d "* ) echo "SKIPPING: make $(basename $@) in $$d" ;; \
		*) $(MAKE) -C $$d $(basename $@) ;; \
		esac ; \
	done
