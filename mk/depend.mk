# Libreswan Makefile dependencies and rules
#
# Copyright (C) 2015 Andrew Cagney
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

# list of files requiring dependency generation
ifndef OBJS
$(error define OBJS)
endif
# cflags for this variant of the compile comand
ifndef CFLAGS
$(error define CFLAGS)
endif

# In addition to compiling the .c file to .o, generate a dependency
# file.  Force all output to the build directory.  $(basename
# $(notdir)) is an approximation of UNIX basename.
#
# -MP: add a fake header target for when a header is deleted
# -MMD: only list user header files
# -MT: the target (otherwise $(builddir)/$(notdir $@) is used
# -MF: where to write the dependency

.c.o:
	$(CC) $(CFLAGS) \
		-MF $(builddir)/$(basename $(notdir $@)).d \
		-MP -MMD -MT $@ \
		-o $(builddir)/$(notdir $@) \
		-c $(abspath $<)

# Assume each source file has its own generated dependency file that
# is updated whenever the corresponding output is updated.  Given
# these files, create an include file that includes them.

mk.depend.file := $(lastword $(MAKEFILE_LIST))
mk.depend.dependencies.file := $(builddir)/Makefile.depend.mk
$(mk.depend.dependencies.file): $(srcdir)/Makefile $(mk.depend.file) | $(builddir)
	set -e ; \
	for f in $(OBJS) ; do \
		case $$f in \
			*.c ) echo "-include \$$(builddir)/$$(basename $$f .c).d # $$f" ;; \
			*.o ) echo "-include \$$(builddir)/$$(basename $$f .o).d # $$f" ;; \
			* ) echo "# $$f ignored by Makefile.dep" ;; \
		esac ; \
	done > $@.tmp
	mv $@.tmp $@

clean: mk.depend.clean
.PHONY: mk.depend.clean
mk.depend.clean:
	rm -f $(mk.depend.dependencies.file)
	rm -f $(builddir)/*.d

-include $(mk.depend.dependencies.file)
