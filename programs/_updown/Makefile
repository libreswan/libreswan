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
# RCSID $Id: Makefile,v 1.8.2.1 2005/07/21 22:34:22 ken Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGRAM=_updown
PROGRAMDIR=${LIBDIR}

include ${srcdir}../Makefile.program


#
# $Log: Makefile,v $
# Revision 1.8.2.1  2005/07/21 22:34:22  ken
# Dump old posix _updown and use _updown.ip2.in all the time
#
# Revision 1.8  2005/07/21 20:40:53  ken
# remove obsolete _updown.c
#
# Revision 1.7  2004/12/18 18:13:38  mcr
# 	adjusted Makefiles so that ${OBJDIR} builds work.
#
# Revision 1.6  2004/04/03 19:44:44  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.5  2003/04/10 17:33:43  mcr
# 	_updown.in is now generated
#
# Revision 1.4  2003/04/07 16:07:07  mcr
# 	introduced iproute2 version of _updown.
#
# Revision 1.3  2002/08/02 16:01:47  mcr
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

