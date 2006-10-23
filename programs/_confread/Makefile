# Makefile for miscelaneous programs
# Copyright (C) 2002-2006  Michael Richardson	<mcr@xelerance.com>
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
# RCSID $Id: Makefile,v 1.7 2005/08/16 02:02:00 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

EXTRA5MAN=ipsec.conf.5
CONFFILES=ipsec.conf
EXCONFILES=ipsec.win2k.conf

CONFDSUBDIR=policies
CONFDFILES=clear clear-or-private private-or-clear private block

ipsec.conf.5.xml: d.ipsec.conf/*.xml
	cat d.ipsec.conf/*.xml >ipsec.conf.5.xml

diff:	ipsec.conf.5.xml
	diff -B -w -u ipsec.conf.5.xml ipsec.conf.5.xml-ref

include ${srcdir}../Makefile.program

