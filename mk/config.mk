# Libreswan pathnames and other master configuration
#
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
# Copyright (C) 2015-2016 Tuomo Soini <tis@foobar.fi>
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
#
# TODO: Some creative ifeq ($(BUILDENV,xxx) to automatically determine
# where we are building on and disable things (eg KLIPS on OSX)

#  Doc:		man make
#  Doc:		http://www.gnu.org/software/make/manual/make.html

# Include any local Makefile.inc.local; local.mk is a wrapper
# that deals with multiple include issues.
include ${LIBRESWANSRCDIR}/mk/local.mk

# Pull in the target/build/host description and get a definition of
# OBJDIR, BUILDENV, et.al.
include ${LIBRESWANSRCDIR}/mk/objdir.mk

# Pull in OSDEP specific makefile stub.
#
# Don't try to deal with OS family variants (debian vs fedora vs ...)
# needing different build options (e.g., auditing, fips).  Instead,
# put all that code in the OS family ${BUILDENV}.mk file - the logic
# ends up being a horrible mess so that hopefully keeps it a little
# contained.
#
# Using the "build" machine to select "target" configuration options
# is, to say the least, a little weird.  It's "historic".
include ${LIBRESWANSRCDIR}/mk/defaults/${BUILDENV}.mk

# Variables in this file with names starting with INC_ are not for use
# by Makefiles which include it; they are subject to change without warning.
#
# "Final" and "finally" refer to where the files will end up on the
# running IPsec system, as opposed to where they get installed by our
# Makefiles.  (The two are different for cross-compiles and the like,
# where our Makefiles are not the end of the installation process.)
# Paths with FINAL in their names are the only ones that the installed
# software itself depends on.  (Very few things should know about the
# FINAL paths; think twice and consult Tuomo before making something new
# depend on them.)  All other paths are install targets.
# See also DESTDIR, below.
#
# Note: Variables here are for Makefiles and build system only.
# IPSEC_ prefixed variables are to be used in source code


### boilerplate, do not change, various scripts use extended BASH syntax!
SHELL=/bin/bash
export SHELL

### install pathnames

# DESTDIR can be used to supply a prefix to all install targets.
# (Note that "final" pathnames, signifying where files will eventually
# reside rather than where install puts them, are exempt from this.)
# The prefixing is done in this file, so as to have central control over
# it; DESTDIR itself should never appear in any other Makefile.
DESTDIR?=

# "local" part of tree, used in building other pathnames
INC_USRLOCAL?=/usr/local

# PUBDIR is where the "ipsec" command goes; beware, many things define PATH
# settings which are assumed to include it (or at least, to include *some*
# copy of the "ipsec" command).
PUBDIR?=$(DESTDIR)$(INC_USRLOCAL)/sbin

# BINDIR is where sub-commands get put, FINALBINDIR is where the "ipsec"
# command will look for them when it is run. Also called LIBEXECDIR.
FINALLIBEXECDIR?=$(INC_USRLOCAL)/libexec/ipsec
LIBEXECDIR?=$(DESTDIR)$(FINALLIBEXECDIR)

FINALBINDIR?=$(FINALLIBEXECDIR)
BINDIR?=$(LIBEXECDIR)


# SBINDIR is where the user interface command goes.
FINALSBINDIR?=$(INC_USRLOCAL)/sbin
SBINDIR?=$(DESTDIR)$(FINALSBINDIR)



# where the appropriate manpage tree is located
# location within INC_USRLOCAL
INC_MANDIR?=man
# the full pathname
MANTREE?=$(DESTDIR)$(INC_USRLOCAL)/$(INC_MANDIR)

# where configuration files go
FINALSYSCONFDIR?=/etc

# final configuration file
FINALCONFFILE?=$(FINALSYSCONFDIR)/ipsec.conf
CONFFILE?=$(DESTDIR)$(FINALCONFFILE)

FINALCONFDIR?=$(FINALSYSCONFDIR)

CONFDIR?=$(DESTDIR)$(FINALCONFDIR)
SYSCONFDIR?=$(DESTDIR)$(FINALSYSCONFDIR)

FINALCONFDDIR?=$(FINALCONFDIR)/ipsec.d
CONFDDIR?=$(DESTDIR)$(FINALCONFDDIR)

FINALNSSDIR?=$(FINALCONFDIR)/ipsec.d
NSSDIR?=$(DESTDIR)$(FINALNSSDIR)

# sample configuration files go into
INC_DOCDIR?=share/doc
FINALEXAMPLECONFDIR?=$(INC_USRLOCAL)/$(INC_DOCDIR)/libreswan
EXAMPLECONFDIR?=$(DESTDIR)$(FINALEXAMPLECONFDIR)

FINALDOCDIR?=$(INC_USRLOCAL)/$(INC_DOCDIR)/libreswan
DOCDIR?=$(DESTDIR)$(FINALDOCDIR)

# where per-conn pluto logs go
FINALVARDIR?=/var
VARDIR?=$(DESTDIR)$(FINALVARDIR)
FINALLOGDIR?=$(FINALVARDIR)/log
LOGDIR?=$(DESTDIR)$(FINALLOGDIR)

# Note: this variable gets passed in, as in "make INITSYSTEM=systemd"
INITSYSTEM ?= $(shell $(SHELL) $(top_srcdir)/packaging/utils/lswan_detect.sh init)

# An attempt is made to automatically figure out where boot/shutdown scripts
# will finally go:  the first directory in INC_RCDIRS which exists gets them.
# If none of those exists (or INC_RCDIRS is empty), INC_RCDEFAULT gets them.
# With a non-null DESTDIR, INC_RCDEFAULT will be used unless one of the
# INC_RCDIRS directories has been pre-created under DESTDIR.
INC_RCDIRS?=/etc/rc.d/init.d /etc/rc.d /etc/init.d /sbin/init.d
INC_RCDEFAULT?=/etc/rc.d/init.d

# RCDIR is where boot/shutdown scripts go; FINALRCDIR is where they think
# will finally be (so utils/Makefile can create a symlink in BINDIR to the
# place where the boot/shutdown script will finally be, rather than the
# place where it is installed).
FINALRCDIR?=$(shell for d in $(INC_RCDIRS) ; \
		do if test -d $(DESTDIR)/$$d ; \
		then echo $$d ; exit 0 ; \
		fi ; done ; echo $(INC_RCDEFAULT) )
RCDIR?=$(DESTDIR)$(FINALRCDIR)



### kernel pathnames

# Kernel location:  where patches are inserted, where kernel builds are done.

# this is a hack using the wildcard to look for existence of a file/dir
ifneq ($(wildcard /usr/src/linux-2.6),)
KERNELSRC?=/usr/src/linux-2.6
else
ifneq ($(wildcard /usr/src/linux-2.4),)
KERNELSRC?=/usr/src/linux-2.4
else
KERNELSRC?=/lib/modules/$(shell uname -r)/build
endif
endif

# where kernel configuration outputs are located
KCFILE=$(KERNELSRC)/.config
ACFILE=$(KERNELSRC)/include/linux/autoconf.h
VERFILE=$(KERNELSRC)/include/linux/version.h

# where KLIPS kernel module is install
OSMOD_DESTDIR?=net/ipsec

# What command to use to load the modules. openwrt does not have modprobe
# Using -b enables blacklisting - this is needed for some known bad
# versions of crypto acceleration modules.
MODPROBEBIN?=modprobe
MODPROBEARGS?=--quiet --use-blacklist

### misc installation stuff

# what program to use when installing things
INSTALL?=install

# flags to the install program, for programs, manpages, and config files
# -b has install make backups (n.b., unlinks original), --suffix controls
# how backup names are composed.
# Note that the install procedures will never overwrite an existing config
# file, which is why -b is not specified for them.
INSTBINFLAGS?=-b --suffix=.old
INSTSUIDFLAGS?=--mode=u+rxs,g+rx,o+rx --group=root -b --suffix=.old

# busybox install is not emulating a real install command well enough
SWANCHECKLINK=$(shell readlink /usr/bin/install)
ifeq ($(SWANCHECKLINK /bin/busybox),)
INSTBINFLAGS=
INSTSUIDFLAGS=-m 0755 -g root -o root
endif


INSTMANFLAGS?=--mode=0644
INSTCONFFLAGS?=--mode=0644
# For OSX use
#INSTBINFLAGS?=-b -B .old
#INSTSUIDFLAGS?=--mode=u+rxs,g+rx,o+rx --group=root -b -B .old

# flags for bison, overrode in packages/default/foo
BISONOSFLAGS?=

# XXX: Don't add NSSFLAGS to USERLAND_CFLAGS for now.  It needs to go
# after -I$(top_srcdir)/include and fixing that is an entirely
# separate cleanup.
NSSFLAGS?=$(shell pkg-config --cflags nss)
# We don't want to link against every library pkg-config --libs nss
# returns
NSS_LDFLAGS ?= -lnss3 -lnspr4

# To build with clang, use: scan-build make programs
#GCC=clang
GCC?=gcc

MAKE?=make

# You can compile using Electric Fence - this is used for running the test suite
# EFENCE=-lefence
EFENCE?=

# Enable AddressSanitizer - see https://libreswan.org/wiki/Compiling_with_AddressSanitizer
# requires clang or gcc >= 4.8 and libasan. Do not combine with Electric Fence and do not
# run pluto with --leak-detective
# ASAN=-fsanitize=address
ASAN?=

### misc configuration, included here in hopes that other files will not
### have to be changed for common customizations.

KLIPSCOMPILE?=-O2 -DCONFIG_KLIPS_ALG -DDISABLE_UDP_CHECKSUM
# You can also run this before starting libreswan on glibc systems:
#export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

# extra link flags
USERLINK?=-Wl,-z,relro,-z,now -g -pie ${EFENCE} ${ASAN}

PORTINCLUDE?=

# command used to link/copy KLIPS into kernel source tree
# There are good reasons why this is "ln -s"; only people like distribution
# builders should ever change it.
KLIPSLINK?=ln -s -f

# extra options for use in kernel build
KERNMAKEOPTS?=

# kernel Makefile targets to be done before build
# Can be overridden if you are *sure* your kernel doesn't need them.  (2.2.xx
# and later reportedly do not.)
KERNDEP?=dep
KERNCLEAN?=clean

# kernel make name:  zImage for 2.0.xx, bzImage for 2.2.xx and later, and
# boot on non-x86s (what ever happened to standards?)
INC_B?=$(shell test -d $(DIRIN22) && echo b)
KERNEL?=$(shell if expr " `uname -m`" : ' i.86' >/dev/null ; \
	then echo $(INC_B)zImage ; \
	else echo boot ; \
	fi)

# look for POD2MAN command
POD2MAN?=$(shell which pod2man | grep / | head -n1)

## build environment variations
#
# USE_ variables determine if features are compiled into Libreswan.
#       these let you turn on/off specific features
# HAVE_ variables let you tell Libreswan what system related libraries
#       you may or maynot have

# Enable support for DNSSEC. This requires the unbound library
USE_DNSSEC?=true

# For systemd start/stop notifications and watchdog feature
# We only enable this by default if used INITSYSTEM is systemd
ifeq ($(INITSYSTEM),systemd)
USE_SYSTEMD_WATCHDOG?=true
SD_RESTART_TYPE?="always"
SD_PLUTO_OPTIONS?="--leak-detective"
else
USE_SYSTEMD_WATCHDOG?=false
endif

# Figure out ipsec.service file Type= option
ifeq ($(USE_SYSTEMD_WATCHDOG),true)
SD_TYPE=notify
SD_WATCHDOGSEC?=200
else
SD_TYPE=simple
endif

# Do we want all the configuration files like ipsec.conf and ipsec.secrets
# and any certificates to be in a single directory defined by
# FINALCONFDDIR?
USE_SINGLE_CONF_DIR?=false

# Build support for KEY RR
# this will become false in the future, as all OE sites transition to
# using IPSECKEY instead of KEY records.  See references to 'Flag Day'
# Except this to change in Q1 2011
USE_KEYRR?=true

# Build support for Linux 2.4 and 2.6 KLIPS kernel level IPsec support
# for pluto
USE_KLIPS?=true

# Build support for 2.6 KLIPS/MAST variation in pluto
USE_MAST?=false

# MAST requires KLIPS
ifeq ($(USE_MAST),true)
USE_KLIPS=true
endif

# MAST is generally a prerequisite for SAREF support in applications
USE_SAREF_KERNEL?=false

# Build support for Linux NETKEY (XFRM) kernel level IPsec support for
# pluto (aka "native", "kame")
USE_NETKEY?=true

# KLIPS needs PFKEYv2, but sometimes we want PFKEY without KLIPS
# Note: NETLINK does not use PFKEY, but it does share some code,
# so it is required for NETKEY as well.
ifeq ($(USE_KLIPS),true)
USE_PFKEYv2=true
else
ifeq ($(USE_NETKEY),true)
USE_PFKEYv2=true
endif
endif

# include support for BSD/KAME IPsec in pluto (on *BSD and OSX)
USE_BSDKAME?=false
ifeq ($(USE_BSDKAME),true)
USE_NETKEY=false
USE_KLIPS=false
endif

# include PAM support for XAUTH when available on the platform

ifeq ($(OSDEP),linux)
USE_XAUTHPAM?=true
endif
ifeq ($(OSDEP),bsd)
USE_XAUTHPAM?=true
endif
ifeq ($(OSDEP),darwin)
USE_XAUTHPAM?=true
endif
ifeq ($(OSDEP),sunos)
USE_XAUTHPAM?=true
endif

# Build support for integrity check for libreswan on startup
USE_FIPSCHECK?=false
FIPSPRODUCTCHECK?=/etc/system-fips

# Build support for the Linux Audit system
ifeq ($(OSDEP),linux)
USE_LINUX_AUDIT?=false
endif

# Enable Labeled IPSec Functionality (requires SElinux)
USE_LABELED_IPSEC?=false

# Support for LIBCAP-NG to drop unneeded capabilities for the pluto daemon
USE_LIBCAP_NG?=true
ifeq ($(OSDEP),darwin)
USE_LIBCAP_NG=false
endif

# Support for Network Manager
USE_NM?=true
ifeq ($(OSDEP),darwin)
USE_NM=false
endif

# Include LDAP support (currently used for fetching CRLs)
USE_LDAP?=false

# Include libcurl support (currently used for fetching CRLs)
USE_LIBCURL?=true

# should we include additional (strong) algorithms?  It adds a measureable
# amount of code space to pluto, and many of the algorithms have not had
# the same scrutiny that AES and 3DES have received, but offers possibilities
# of switching away from AES/3DES quickly.
USE_EXTRACRYPTO?=true

# Do we want to limit the number of ipsec connections artificially
USE_IPSEC_CONNECTION_LIMIT?=false
IPSEC_CONNECTION_LIMIT?=250

# For Angstrom linux with broken popen() set to true. See bug #1067
HAVE_BROKEN_POPEN?=false

NONINTCONFIG=oldconfig

-include ${LIBRESWANSRCDIR}/Makefile.ver

# make sure we only run this once per build,  its too expensive to run
# every time Makefile.inc is included
ifndef IPSECVERSION
IPSECVERSION:=$(shell ${LIBRESWANSRCDIR}/packaging/utils/setlibreswanversion ${IPSECBASEVERSION} ${LIBRESWANSRCDIR})
export IPSECVERSION
# VID is a somewhat shortened version, eg "3.5" or "3.5-xxx"
IPSECVIDVERSION:=$(shell echo ${IPSECVERSION} | sed 's/^\([^-]*\)-\([^-]*\)-.*/\1-\2/')
export IPSECVIDVERSION
endif

# On MAC OSX , we have to use YACC and not BISON. And use different backup
# file suffix.
ifeq ($(BUILDENV),"darwin")
USE_YACC?=true
INSTBINFLAGS=-D -b -B .old
INSTSUIDFLAGS=--mode=u+rxs,g+rx,o+rx --group=root -b -B .old
endif

OBJDIRTOP?=${LIBRESWANSRCDIR}/${OBJDIR}

#
#  Paranoia says to export these just to sure:
export OBJDIR
export OBJDIRTOP

### paths within the source tree

KLIPSINC=${LIBRESWANSRCDIR}/linux/include
KLIPSSRCDIR=${LIBRESWANSRCDIR}/linux/net/ipsec
#KLIPSSRCDIR=/mara1/git/klips/net/ipsec

LIBSWANDIR=${LIBRESWANSRCDIR}/lib/libswan
LIBRESWANLIB=${OBJDIRTOP}/lib/libswan/libswan.a
LSWLOGLIB=${OBJDIRTOP}/lib/libswan/liblswlog.a

LIBDESSRCDIR=${LIBRESWANSRCDIR}/linux/crypto/ciphers/des
LIBMD5=${OBJDIRTOP}/lib/libcrypto/libmd5/libmd5.a
LIBSHA1=${OBJDIRTOP}/lib/libcrypto/libsha1/libsha1.a
LIBTWOFISH=${OBJDIRTOP}/lib/libcrypto/libtwofish/libtwofish.a
LIBSERPENT=${OBJDIRTOP}/lib/libcrypto/libserpent/libserpent.a
LIBSHA2=${OBJDIRTOP}/lib/libcrypto/libsha2/libsha2.a
LIBAES_XCBC=${OBJDIRTOP}/lib/libcrypto/libaes_xcbc/libaes_xcbc.a
CRYPTOLIBS=${LIBSHA1} ${LIBMD5} ${LIBSHA2} ${LIBAES_XCBC}

ifeq ($(USE_EXTRACRYPTO),true)
CRYPTOLIBS+= ${LIBSERPENT} ${LIBTWOFISH}
endif

WHACKLIB=${OBJDIRTOP}/lib/libwhack/libwhack.a
IPSECCONFLIB=${OBJDIRTOP}/lib/libipsecconf/libipsecconf.a

# export everything so that scripts can use them.
export LIBSWANDIR LIBRESWANSRCDIR ARCH PORTINCLUDE
export LIBRESWANLIB LSWLOGLIB
export LIBDESSRCDIR
export LIBMD5 LIBSHA1 LIBTWOFISH LIBSERPENT
export LIBSHA2 LIBAES_XCBC CRYPTOLIBS WHACKLIB IPSECCONFLIB

#KERNELBUILDMFLAGS=--debug=biv V=1

IPSEC_SECRETS_FILE ?= $(FINALCONFDIR)/ipsec.secrets

# how to do variable substitution in sed-transformed files
TRANSFORM_VARIABLES = sed -e "s:@IPSECVERSION@:$(IPSECVERSION):g" \
			-e "/@${OSDEP}_START@/,/@${OSDEP}_END@/d" \
			-e "s:@EXAMPLECONFDIR@:$(EXAMPLECONFDIR):g" \
			-e "s:@FINALBINDIR@:$(FINALBINDIR):g" \
			-e "s:@FINALCONFDDIR@:$(FINALCONFDDIR):g" \
			-e "s:@FINALNSSDIR@:$(FINALNSSDIR):g" \
			-e "s:@FINALCONFDIR@:$(FINALCONFDIR):g" \
			-e "s:@FINALCONFFILE@:$(FINALCONFFILE):g" \
			-e "s:@FINALDOCDIR@:$(FINALDOCDIR):g" \
			-e "s:@FINALEXAMPLECONFDIR@:$(FINALEXAMPLECONFDIR):g" \
			-e "s:@FINALLIBEXECDIR@:$(FINALLIBEXECDIR):g" \
			-e "s:@FINALRCDIR@:$(FINALRCDIR):g" \
			-e "s:@FINALSBINDIR@:$(FINALSBINDIR):g" \
			-e "s:@FINALSYSCONFDIR@:$(FINALSYSCONFDIR):g" \
			-e "s:@FINALVARDIR@:$(FINALVARDIR):g" \
			-e "s:@IPSEC_CONF@:$(FINALCONFFILE):g" \
			-e "s:@IPSEC_CONFDDIR@:$(FINALCONFDDIR):g" \
			-e "s:@IPSEC_NSSDIR@:$(FINALNSSDIR):g" \
			-e "s:@IPSEC_DIR@:$(FINALBINDIR):g" \
			-e "s:@IPSEC_EXECDIR@:$(FINALLIBEXECDIR):g" \
			-e "s:@IPSEC_VARDIR@:$(FINALVARDIR):g" \
			-e "s:@IPSEC_SBINDIR@:$(FINALSBINDIR):g" \
			-e "s:@IPSEC_SECRETS_FILE@:$(IPSEC_SECRETS_FILE):g" \
			-e "s:@MODPROBEBIN@:$(MODPROBEBIN):g" \
			-e "s:@MODPROBEARGS@:$(MODPROBEARGS):g" \
			-e "s:@USE_DEFAULT_CONNS@:$(USE_DEFAULT_CONNS):g" \
			-e "s:@SD_TYPE@:$(SD_TYPE):g" \
			-e "s:@SD_RESTART_TYPE@:$(SD_RESTART_TYPE):g" \
			-e "s:@SD_PLUTO_OPTIONS@:$(SD_PLUTO_OPTIONS):g" \
			-e "s:@SD_WATCHDOGSEC@:$(SD_WATCHDOGSEC):g" \

# For KVM testing setup
#POOL?=${LIBRESWANSRCDIR}/pool
POOL?=/vol/pool
# support types are fedora and ubuntu
OSTYPE?=fedora
OSMEDIA?=http://download.fedoraproject.org/pub/fedora/linux/releases/21/Server/x86_64/os/

# Ubuntu media
# OSTYPE?=ubuntu
# OSMEDIA?=http://ftp.ubuntu.com/ubuntu/dists/precise/main/installer-amd64/

# Now that all the configuration variables are defined, use them to
# define USERLAND_CFLAGS
include ${LIBRESWANSRCDIR}/mk/userland-cflags.mk
