# Openswan TCL/Pluto Mix (TPM)
# Pronounced, "TaProoM"
#
# Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
# RCSID $Id: Makefile,v 1.8 2005/10/02 21:42:25 mcr Exp $


OPENSWANSRCDIR?=$(shell cd ../../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


SRCS=tpm.c state.i pbs.c stock.c

OBJS=$(filter %.o,$(SRCS:.c=.o) $(SRCS:.i=.o))

LIBA=libtpm.a

include ${srcdir}../Makefile.options

# Original flags
CFLAGS=${DEFINES} -I${srcdir}.. -I${srcdir}
CFLAGS+=${USERCOMPILE} 
GENINC=${PORTINCLUDE} -I${OPENSWANSRCDIR}/include -I${OPENSWANSRCDIR}/linux/include 
CFLAGS+=${GENINC} 

ARFLAGS=crvs
MANS=

.PHONY:	all install clean l t lt tar check depend checkprograms

# we can't do tests with two conditions, but we can concatenate the strings
SHOULDWERESTART=${USE_OBJDIR}$(wildcard tpm.c)
ifeq ($(SHOULDWERESTART),truetpm.c)
all programs clean install:
	cd ${OPENSWANSRCDIR} && cd ${OBJDIRTOP}/programs/pluto/tpm && make $@
else
all:	$(LIBA) ${LIBL}
programs: $(LIBA) ${LIBL}

clean:	cleanall
install: doinstall

endif
doinstall:
	@mkdir -p $(MANDIR)
	@for f in $(MANS) ; \
	do \
		$(INSTALL) $(INSTMANFLAGS) $(MANSRCDIR)/$$f $(MANDIR)/ipsec_$$f || exit 1 ; \
	done

install_file_list:
	@for f in $(MANS) ; \
	do \
		echo $(MANDIR)/ipsec_$$f;\
	done;

$(LIBA): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBA) $(OBJS)

$(LIBL): $(LOGOBJS)
	$(AR) $(ARFLAGS) $(LIBL) $(LOGOBJS)

$(OBJS):	$(HDRS)

$(LOGOBJS):	$(HDRS)

cleanall:
	rm -f *.o state_wrap.c libtpm.a

%.o : %.i
	swig -tcl8 ${GENINC} -o $*_wrap.c $<
	${CC} ${CFLAGS} -c -o $@ $*_wrap.c

check:
	echo no checks in tpm right now.

depend:
	@(ls $(DISTSRC) | grep '\.c' | xargs gcc -MM ${COPTS} ${ALLFLAGS} ) | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend

-include ${srcdir}Makefile.depend

checkprograms:

# DO NOT DELETE
