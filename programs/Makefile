# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015,2017,2022 Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

ifndef top_srcdir
include ../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk

SUBDIRS=

# first
SUBDIRS += pluto
SUBDIRS += whack

SUBDIRS += _import_crl
SUBDIRS += _plutorun
SUBDIRS += _secretcensor
SUBDIRS += _unbound-hook
SUBDIRS += _updown
SUBDIRS += addconn
SUBDIRS += algparse
SUBDIRS += auto
SUBDIRS += barf
SUBDIRS += cavp
SUBDIRS += ecdsasigkey
SUBDIRS += ipsec
SUBDIRS += letsencrypt
SUBDIRS += look
SUBDIRS += newhostkey
SUBDIRS += readwriteconf
SUBDIRS += rsasigkey
SUBDIRS += setup

ifneq ($(BSD_VARIANT),)
SUBDIRS += show.bsd
else
SUBDIRS += show
endif

SUBDIRS += showhostkey
SUBDIRS += showroute

ifneq ($(BSD_VARIANT),)
SUBDIRS += verify.bsd
else
SUBDIRS += verify
endif

ifeq ($(USE_PORTEXCLUDES),true)
SUBDIRS += portexcludes
endif

ifeq ($(USE_XFRM),true)
SUBDIRS +=  _updown.xfrm
endif

ifneq ($(LINUX_VARIANT),)
SUBDIRS += _stackmanager
endif

ifneq ($(BSD_VARIANT),)
SUBDIRS += _realsetup.bsd
SUBDIRS += _updown.bsd
endif

include $(top_srcdir)/mk/targets.mk
