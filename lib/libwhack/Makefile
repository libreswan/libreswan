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
include $(top_srcdir)/mk/targets.mk

SRCS=whacklib.c aliascomp.c

OBJS=${SRCS:.c=.o}

KLIPSD=${LIBRESWANSRCDIR}/linux/include
KLIPSSRCDIR=${LIBRESWANSRCDIR}/linux/net/ipsec

VPATH+= ${KLIPSSRCDIR}

LIB=libwhack.a

# Original flags
INCLUDES=-I. -I${KLIPSSRCDIR} -I${KLIPSD} -I${LIBRESWANSRCDIR}
INCLUDES+=-I${LIBRESWANSRCDIR}/include

CFLAGS+=${PORTINCLUDE} ${INCLUDES}
# XXX: hack until everything uses a consistent .c.o rule
CFLAGS+=$(USERLAND_CFLAGS)
CFLAGS+=$(NSSFLAGS)

ARFLAGS=crvs

# XXX: Switch directory hack
local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) buildall

local-clean-base:
	rm -f $(foreach f,$(OBJS) $(LIB), $(builddir)/$(f))

buildall: $(LIB)
list-local-base:
	@: never nothing to do

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

MK_DEPEND_CFLAGS = $(CFLAGS) ${ALLFLAGS}
MK_DEPEND_FILES = $(SRCS)
include $(top_srcdir)/mk/depend.mk
