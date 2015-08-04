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

LIBRARY=ipsecconf
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

ONEFILE=parser.y
SRCS=confread.c confwrite.c starterwhack.c starterlog.c
SRCS+=parser.tab.c lex.yy.c keywords.c oeconns.c
SRCS+=interfaces.c

#enable to get lots more debugging about semantics.
#CFLAGS+=-DPARSER_TYPE_DEBUG

OBJS=${SRCS:.c=.o}

ifdef top_srcdir
include ${top_srcdir}/mk/library.mk
else
include ../../mk/library.mk
endif

# Hack to force the generated files to be built first.  Not too bad
# since all the $(OBJS) indirectly depend on the header anyway.
$(OBJS): parser.tab.h

# Use UNIX basename to strip off the directory. Use grep to workaround flex < 2.5.35
lex.yy.c: parser.l
	cd $(builddir) && $(LEX) -t $(srcdir)/$$(basename $<) | grep -v '^extern int isatty' > $@

# Use wild card rule so that GNU Make knows that both are output from
# a single recipe.
# - sed command for workaround for older bison vs GCC warning
# - avoid sed -i which somehow causes unwritable files
#   on fedora 20 with 9p filesystem mount
%.tab.h %.tab.c: %.y
	cd $(builddir) && \
	$(BISON) ${BISONOSFLAGS} -v -d $(srcdir)/$$(basename $<) && \
	sed -e '/^ *#/s/if YYENABLE_NLS/if defined(YYENABLE_NLS) \&\& YYENABLE_NLS/' \
		-e '/^ *#/s/if YYLTYPE_IS_TRIVIAL/if defined(YYLTYPE_IS_TRIVIAL) \&\& YYLTYPE_IS_TRIVIAL/' \
		$$(basename $< .y).tab.c >SEDTMP$$$$ && \
	mv SEDTMP$$$$ $$(basename $< .y).tab.c

clean: parser-clean
.PHONY: parser-clean
parser-clean:
	cd $(builddir) && $(RM) -f SEDTMP* *.tab.[cdho] *.dot *.output lex.yy.[cdho]
