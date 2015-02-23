# Libreswan library for parsing configuration files
#
# Copyright (C) 2005 Michael Richardson <mcr@xelerance.com> Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

ifndef top_srcdir
include ../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk

LIBRARY=ipsecconf
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

ONEFILE=parser.y
SRCS=confread.c confwrite.c starterwhack.c starterlog.c 
SRCS+=parser.tab.c lex.yy.c keywords.c oeconns.c
SRCS+=interfaces.c

#enable to get lots more debugging about semantics.
#CFLAGS+=-DPARSER_TYPE_DEBUG

#ifeq ($(USE_FIPSCHECK),true)
#CFLAGS+=-DFIPS_CHECK
#endif

ifeq ($(USE_NM),true)
CFLAGS+=-DHAVE_NM
endif

ifeq ($(USE_LABELED_IPSEC),true)
CFLAGS+=-DHAVE_LABELED_IPSEC
endif

OBJS=${SRCS:.c=.o} 

include $(top_srcdir)/mk/library.mk

# Hack to force the generated files to be built first.  Not too bad
# since all the $(OBJS) indirectly depend on the header anyway.
$(OBJS): parser.tab.h

# Use UNIX basename to strip off the directory.
lex.yy.c: parser.l
	cd $(builddir) && $(LEX) $(srcdir)/$$(basename $<)

# Use wild card rule so that GNU Make knows that both are output from
# single program.  Use UNIX basename to strip off the directory.
%.tab.h %.tab.c: %.y
	cd $(builddir) && $(BISON) ${BISONOSFLAGS} -v -d $(srcdir)/$$(basename $<)

clean:
	cd $(builddir) && $(RM) -f parser.tab.* lex.yy.*

MK_DEPEND_FILES = $(OBJS)
MK_DEPEND_CFLAGS = $(CFLAGS)
-include $(top_srcdir)/mk/depend.mk
