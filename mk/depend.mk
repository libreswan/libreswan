# Libreswan Makefile dependencies and rules
#
# Copyright (C) 2015 Andrew Cagney
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

# list of files requiring dependency generation
ifndef MK_DEPEND_FILES
$(error define MK_DEPEND_FILES)
endif
# cflags for this variant of the compile comand
ifndef MK_DEPEND_CFLAGS
$(error define MK_DEPEND_CFLAGS)
endif

# In addition to compiling generate a dependency file.
.c.o:
	$(CC) $(MK_DEPEND_CFLAGS) -MMD -c $<

# Assume each source file has its own generated dependency file that
# is updated whenever the corresponding output is updated.  Given
# these files, create an include file that includes them.
 
mk.depend.file := $(lastword $(MAKEFILE_LIST))
mk.depend.dependencies.file := $(builddir)/Makefile.depend.mk
$(mk.depend.dependencies.file): $(srcdir)/Makefile $(mk.depend.file)
	set -e ; \
	for f in $(MK_DEPEND_FILES) ; do \
		case $$f in \
			*.c ) echo "-include $$(basename $$f .c).d # $$f" ;; \
			*.o ) echo "-include $$(basename $$f .o).d # $$f" ;; \
			* ) echo "# $$f ignored by Makefile.dep" ;; \
		esac ; \
	done > $@.tmp
	mv $@.tmp $@

-include $(mk.depend.dependencies.file)

