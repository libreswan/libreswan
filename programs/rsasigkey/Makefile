# Makefile for miscelaneous programs
# Copyright (C) 2002  Michael Richardson	<mcr@freeswan.org>
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

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
include ${LIBRESWANSRCDIR}/Makefile.inc

PROGRAM=rsasigkey
LIBS=${LIBRESWANLIB} -lgmp
LIBS+=${NSSLIBS}

ifeq ($(USE_FIPSCHECK),true)
CFLAGS+=-DFIPS_CHECK -DFIPSPRODUCTCHECK=\"${FIPSPRODUCTCHECK}\"
LIBS+=  -lfipscheck
endif

include ${srcdir}../Makefile.program
