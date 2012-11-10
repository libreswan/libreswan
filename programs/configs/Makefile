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

LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
include ${LIBRESWANSRCDIR}/Makefile.inc

EXTRA5MAN=ipsec.conf.5
CONFFILES=ipsec.conf
EXCONFILES=ipsec.win2k.conf
SOURCEDIR=configs

CONFDSUBDIR=policies
CONFDFILES=clear clear-or-private private-or-clear private block

include ${srcdir}../Makefile.program

ipsec.conf.5: ${srcdir}ipsec.conf.5.xml

${srcdir}ipsec.conf.5.xml: $(wildcard d.ipsec.conf/*.xml) ${srcdir}d.ipsec.conf/order.txt
	cd ${srcdir} && cat `cat ${srcdir}d.ipsec.conf/order.txt` >ipsec.conf.5.xml

diff:	ipsec.conf.5.xml
	diff -B -w -u ipsec.conf.5.xml ipsec.conf.5.xml-ref

