# Openswan library
# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
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
#
# RCSID $Id: Makefile,v 1.20 2005/09/17 21:57:45 mcr Exp $


OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


MANDIR=$(MANTREE)/man3

SRCS=whacklib.c

OBJS=${SRCS:.c=.o} 

KLIPSD=${OPENSWANSRCDIR}/linux/include
KLIPSSRCDIR=${OPENSWANSRCDIR}/linux/net/ipsec
MANSRCDIR=${OPENSWANSRCDIR}/lib/libopenswan

VPATH+= ${KLIPSSRCDIR}

LIB=libwhack.a

# Original flags
INCLUDES=-I. -I${KLIPSSRCDIR} -I${KLIPSD} -I${OPENSWANSRCDIR}
INCLUDES+=-I${OPENSWANSRCDIR}/include 
CFLAGS+=${PORTINCLUDE} ${INCLUDES} 
CFLAGS+=-DDEBUG
CFLAGS+= $(USERCOMPILE)
CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast 

ifeq ($(USE_NAT_TRAVERSAL),true)
CFLAGS+= -DNAT_TRAVERSAL
endif

ARFLAGS=crvs
MANS=

.PHONY:	all install clean l t lt tar check depend checkprograms

# we can't do tests with two conditions, but we can concatenate the strings
SHOULDWERESTART=${USE_OBJDIR}$(wildcard whacklib.c)
ifeq ($(SHOULDWERESTART),truewhacklib.c)
all programs clean install:
	cd ${OPENSWANSRCDIR} && cd ${OBJDIRTOP}/lib/libwhack && ${MAKE} $@
else
all:	$(LIB) ${LIBL}
programs: $(LIB) ${LIBL}
clean:	cleanall
install: doinstall

endif

doinstall:
	@mkdir -p $(MANDIR)
	@for f in $(MANS) ; \
	do \
		$(INSTALL) $(INSTMANFLAGS) $(MANSRCDIR)/$$f $(MANDIR)/ipsec_$$f || exit 1 ; \
	done
	@$(OPENSWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${MANSRCDIR}/$(man)) | \
	while read from to; \
	do \
		ln -s -f ipsec_$$from $(MANDIR)/$$to; \
	done


install_file_list:
	@for f in $(MANS) ; \
	do \
		echo $(MANDIR)/ipsec_$$f;\
	done;
	@$(OPENSWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${MANSRCDIR}/$(man)) | \
	while read from to; \
	do \
		echo $(MANDIR)/$$to; \
	done

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

cleanall:
	rm -rf ${OBJS}

# Gather dependencies caused by explicit #includes within .c files
depend: ${DISTSRC}
	@(ls $(DISTSRC) | grep '\.c' | xargs gcc -MM ${PORTINCLUDE} ${INCLUDES} ${ALLFLAGS} ) | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend

-include ${srcdir}Makefile.depend



