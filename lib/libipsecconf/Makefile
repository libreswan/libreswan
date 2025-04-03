# Libreswan library for parsing configuration files
#
# Copyright (C) 2005 Michael Richardson <mcr@xelerance.com> Xelerance Corporation
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

LIBRARY=ipsecconf
LIB=lib${LIBRARY}.a

SRCS=confread.c confwrite.c starterwhack.c
SRCS+=parser.tab.c lex.yy.c keywords.c
SRCS+=interfaces.c

OBJS=${SRCS:.c=.o}

ifdef top_srcdir
include ${top_srcdir}/mk/library.mk
else
include ../../mk/library.mk
endif

# Hack to force the generated files to be built first.  Not too bad
# since all the $(OBJS) indirectly depend on the header anyway.
$(OBJS): $(builddir)/parser.tab.h

# Avoid flex bugs:
#
# - flex 3.5.4 (centos 5) doesn't allow a space between the '-o'
#   option and the file name.
#
#   Fortunately later versions of flex seem to handle this.
#
# - flex < 2.5.35 generates an invalid extern
#
#   Use sed to strip this out.
#
# - flex on RHEL 7 generates code that provokes GCC to warn
#   about comparing a signed value with an unsigned value
#   (Combination of a new GCC and an old flex).
#
#   Adding one cast makes RHEL 6's GCC unhappy, so we add two.
#   On RHEL 6, i is int and _yybytes_len is int.
#   On RHEL 7, i is int and _yybytes_len is yy_size_t
#   On Fedora 21, i is yy_size_t and _yybytes_len is yy_size_t
#   On some architectures, yy_size_t is wider than int;
#   which makes a mixed comparison OK.
#
# - flex 2.6.0-11 and gcc 4:5.3.1-3 on debian testing (2016-06-18)
#   also warns about comparisons of different kinds, so we add a third
#   fix.
#
# - avoid sed -i which somehow causes unwritable files on fedora 20
#   with 9p filesystem mount.

LEX = flex

$(builddir)/lex.yy.c: scanner.lex
	: no space between -o and scratch output file
	$(LEX) -o$@ --stdout $< | sed \
		-e 's/for ( i = 0; i < _yybytes_len; ++i )$$/for ( i = 0; (yy_size_t)i < (yy_size_t)_yybytes_len; ++i )/' \
		-e '/^extern int isatty.*$$/d' \
		-e 's/if ((int) ((yy_n_chars) + number_to_move) > YY_CURRENT_BUFFER_LVALUE->yy_buf_size) {$$/if (((yy_n_chars) + number_to_move) > YY_CURRENT_BUFFER_LVALUE->yy_buf_size) {/' \
		> $@.tmp
	: install result
	mv $@.tmp $@

# Use wild card rule so that GNU Make knows that both are output from
# a single recipe.
# - sed command for workaround for older bison vs GCC warning
# - avoid sed -i which somehow causes unwritable files
#   on fedora 20 with 9p filesystem mount
# - avoid creating the target file until it is done
# - $* matches %
#
# - run bison from the builddir so that parser.tab.h defines
#   YY_YY_PARSER_TAB_H_INCLUDED and not a macro containing the
#   buildpath.  See parser-controls.h for why.

ifeq ($(USE_YACC),true)
BISON=yacc -b parser
else
BISON=bison
BISONOSFLAGS=-g --verbose
endif

$(builddir)/%.tab.h $(builddir)/%.tab.c: %.y
	cd $(builddir) && $(BISON) ${BISONOSFLAGS} -v --defines=$*.tab.h -o $*.tab.c.tmp $(abs_srcdir)/$*.y
	sed -e '/^ *#/s/if YYENABLE_NLS/if defined(YYENABLE_NLS) \&\& YYENABLE_NLS/' \
	    -e '/^ *#/s/if YYLTYPE_IS_TRIVIAL/if defined(YYLTYPE_IS_TRIVIAL) \&\& YYLTYPE_IS_TRIVIAL/' \
	    < $(builddir)/$*.tab.c.tmp >  $(builddir)/$*.tab.c.sedtmp
	rm $(builddir)/$*.tab.c.tmp
	mv $(builddir)/$*.tab.c.sedtmp $(builddir)/$*.tab.c

clean: parser-clean
.PHONY: parser-clean
parser-clean:
	cd $(builddir) && rm -f *.tab.[cdho] *.dot *.output lex.yy.[cdho] *tmp
