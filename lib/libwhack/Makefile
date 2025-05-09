# Libreswan library
#
# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

ifndef top_srcdir
include ../../mk/dirs.mk
endif
include $(top_srcdir)/mk/config.mk

LIB = libwhack.a

OBJS += aliascomp.o
OBJS += pickle.o
OBJS += send.o

OBJS += $(abs_builddir)/whack_magic.o

# build whack_magic.c using whack_magic.in.c
$(abs_builddir)/whack_magic.c: $(srcdir)/whack_magic.in.c
	rm -f $@.tmp
	sed -e "s/@@WHACK_MAGIC@@/$$(echo $(IPSECVERSION) | cksum | { read s e ; echo $$s; })/" \
	    $(srcdir)/whack_magic.in.c \
	    > $@.tmp
	mv $@.tmp $@

include ${top_srcdir}/mk/library.mk
