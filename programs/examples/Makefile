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
# RCSID $Id: Makefile,v 1.3.6.1 2005/11/01 18:10:07 paul Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

CONFDSUBDIR=examples
CONFDFILES=no_oe.conf l2tp-cert.conf l2tp-cert-orgWIN2KXP.conf l2tp-psk.conf l2tp-psk-orgWIN2KXP.conf

include ${srcdir}../Makefile.program

#
# $Log: Makefile,v $
# Revision 1.3.6.1  2005/11/01 18:10:07  paul
# dopted Jacco's L2TP example configuration files. I changed them slightly
# from his versions to properly support nat-t and to avoid breaking rekey
# attempts for right=%any. I also changed the pathnames to proper ones,
# removed hardcoded IP addresses and removed explicitely loading the roadwarriors
# certificate (and use rightca=%same instead)
#
# Revision 1.3  2004/12/18 18:13:39  mcr
# 	adjusted Makefiles so that ${OBJDIR} builds work.
#
# Revision 1.2  2004/04/03 19:44:45  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.1  2004/01/20 19:24:23  sam
# Adding a template .conf file which will disable OE. Can be "include"d until
# such time as there is an oe=yes|no parameter.
#
# Revision 1.4  2002/12/30 07:02:28  mcr
# 	install empty policygroup files by default.
#
# Revision 1.3  2002/08/02 16:01:03  mcr
# 	moved user visible programs to $PREFIX/libexec, while moving
# 	private files to $PREFIX/lib.
#
# Revision 1.2  2002/06/02 22:02:14  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.1  2002/04/24 07:55:32  mcr
# 	#include ${srcdir}..tches and Makefiles for post-reorg compilation.
#
#
#

