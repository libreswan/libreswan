# Makefile for the ike aggressive denial of service attacker
#
# Copyright (C) 2006  Michael Richardson <mcr@xelerance.com>
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
# RCSID $Id: Makefile,v 1.7 2004/12/18 18:13:39 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGRAM=ike-aggr-dos
OBJS=checksum.o

VPATH += ${OPENSWANSRCDIR}/testing/kunit/libkern

#LIBS=${OPENSWANLIB}
EXTRALIBS=-lpcap

include ${OPENSWANSRCDIR}/programs/Makefile.program


