# ipsec starter Makefile
# Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
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

PROGLIBS=${WHACKLIB} ${IPSECCONFLIB} ${EFENCE} $(NSS_LDFLAGS)

PROGRAM=addconn

# reach into pluto for now.
INCLUDES=-I${LIBRESWANSRCDIR}/programs/pluto
INCLUDES+=-I${SRCDIR}

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif

PROGLIBS+=$(UNBOUND_LDFLAGS)

TAGS:	$(DISTSRC)
	LC_ALL=C etags $(ETAGSFLAGS) $(DISTSRC) $(LIBSWANDIR)/*.[ch]

