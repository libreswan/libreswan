# Libreswan configuration
#
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015,2017-2018 Andrew Cagney
# Copyright (C) 2015-2019 Tuomo Soini <tis@foobar.fi>
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

ifndef config.mk
config.mk = true

# A Makefile wanting to test variables defined below has two choides:
#
# - include config.mk early and use GNU-make's 'ifeq' statement
#
# - include config.mk late, and use $(call if-enabled,VARIABLE,result)
#

if-enabled = $(if $(filter true, $($(strip $(1)))),$(2),$(3))


#
#
# TODO: Some creative ifeq ($(BUILDENV,xxx) to automatically determine
# where we are building on and disable things

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

# -D... goes in here
USERLAND_CFLAGS += -pthread

# should this go in CFLAGS?
USERLAND_CFLAGS += -std=gnu99

#
# Options that really belong in CFLAGS (making for an intuitive way to
# override them).
#
# Unfortunately this file is shared with the kernel which seems to
# have its own ideas on CFLAGS.
#

DEBUG_CFLAGS ?= -g
USERLAND_CFLAGS += $(DEBUG_CFLAGS)

# eventually: -Wshadow -pedantic?
WERROR_CFLAGS ?= -Werror
USERLAND_CFLAGS += $(WERROR_CFLAGS)
WARNING_CFLAGS ?= -Wall -Wextra -Wformat -Wformat-nonliteral -Wformat-security -Wundef -Wmissing-declarations -Wredundant-decls -Wnested-externs
USERLAND_CFLAGS += $(WARNING_CFLAGS)

# _FORTIFY_SOURCE requires at least -O.  Gentoo, pre-defines
# _FORTIFY_SOURCE (to what? who knows!); force it to our preferred
# value.
OPTIMIZE_CFLAGS ?= -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
USERLAND_CFLAGS += $(OPTIMIZE_CFLAGS)

# Dumping ground for an arbitrary set of flags.  Should probably be
# separated out.
USERCOMPILE ?= -fstack-protector-all -fno-strict-aliasing -fPIE -DPIE
USERLAND_CFLAGS += $(USERCOMPILE)

# Basic linking flags
USERLINK ?= -Wl,-z,relro,-z,now -pie
USERLAND_LDFLAGS += -Wl,--as-needed
USERLAND_LDFLAGS += $(USERLINK) $(ASAN)

# Accumulate values in these fields.
# is -pthread CFLAG or LDFLAG
USERLAND_INCLUDES += -I$(srcdir) -I$(builddir) -I$(top_srcdir)/include


### install pathnames

# DESTDIR can be used to supply a prefix to all install targets.
# (Note that "final" pathnames, signifying where files will eventually
# reside rather than where install puts them, are exempt from this.)
# The prefixing is done in this file, so as to have central control over
# it; DESTDIR itself should never appear in any other Makefile.
DESTDIR ?=

# "PREFIX" part of tree, used in building other pathnames.
PREFIX ?= /usr/local

# Compatibility with old INC_USRLOCAL which was changed to PREFIX.
# We will overwrite PREFIX with INC_USRLOCAL untill libreswan 3.32
ifdef INC_USRLOCAL
PREFIX = $(INC_USRLOCAL)
$(warning Warning: Overriding PREFIX with deprecated variable INC_USRLOCAL)
endif

# LIBEXECDIR is where sub-commands get put, FINALLIBEXECDIR is where
# the "ipsec" command will look for them when it is run.
FINALLIBEXECDIR ?= $(PREFIX)/libexec/ipsec
LIBEXECDIR ?= $(DESTDIR)$(FINALLIBEXECDIR)

ifdef BINDIR
$(error ERROR: Deprecated BINDIR variable set, use LIBEXECDIR instead)
endif

# SBINDIR is where the user interface command goes.
FINALSBINDIR ?= $(PREFIX)/sbin
SBINDIR ?= $(DESTDIR)$(FINALSBINDIR)

# Error out if somebody try to use deprecated PUBDIR.
ifdef PUBDIR
$(error ERROR: deprecated variable PUBDIR is set, use SBINDIR instead)
endif

# where the appropriate manpage tree is located
FINALMANDIR ?= $(PREFIX)/share/man
ifdef INC_MANDIR
FINALMANDIR = $(PREFIX}/$(INC_MANDIR)
$(warning Warning: Overriding FINALMANDIR with deprecated INC_MANDIR variable)
endif
# the full pathname
MANDIR ?= $(DESTDIR)$(FINALMANDIR)

# Compatibility with old MANTREE which was changed to MANDIR.
# We will overwrite MANDIR with MANTREE untill libreswan 3.32
ifdef MANTREE
MANDIR = $(MANTREE)
$(warning Warning: Overriding MANDIR with deprecated variable MANTREE)
endif

# where configuration files go
FINALSYSCONFDIR ?= /etc

# run dir - defaults to /run/pluto
# Some older systems might need to set this to /var/run/pluto
FINALRUNDIR ?= /run/pluto
RUNDIR ?= $(DESTDIR)$(FINALRUNDIR)

# final configuration file
FINALCONFFILE ?= $(FINALSYSCONFDIR)/ipsec.conf
CONFFILE ?= $(DESTDIR)$(FINALCONFFILE)

FINALCONFDIR ?= $(FINALSYSCONFDIR)

CONFDIR ?= $(DESTDIR)$(FINALCONFDIR)
SYSCONFDIR ?= $(DESTDIR)$(FINALSYSCONFDIR)

FINALCONFDDIR ?= $(FINALCONFDIR)/ipsec.d
CONFDDIR ?= $(DESTDIR)$(FINALCONFDDIR)

FINALNSSDIR ?= /etc/ipsec.d
# Debian uses /var/lib/ipsec/nss
#FINALNSSDIR ?= /var/lib/ipsec/nss
NSSDIR ?= $(DESTDIR)$(FINALNSSDIR)

# where dynamic PPKs go, for now
FINALPPKDIR ?= $(FINALCONFDDIR)
PPKDIR ?= $(DESTDIR)$(FINALPPKDIR)

# We will overwrite FINALDOCDIR with INC_DOCDIR untill libreswan 3.32
ifdef INC_DOCDIR
FINALDOCDIR = $(PREFIX}/$(INC_DOCDIR)/libreswan
$(warning Warning: Overriding FINALDOCDIR with deprecated INC_DOCDIR variable)
endif

# Documentation directory
FINALDOCDIR ?= $(PREFIX)/share/doc/libreswan
DOCDIR ?= $(DESTDIR)$(FINALDOCDIR)

# sample configuration files go into
FINALEXAMPLECONFDIR ?= $(FINALDOCDIR)
EXAMPLECONFDIR ?= $(DESTDIR)$(FINALEXAMPLECONFDIR)


# where per-conn pluto logs go
FINALVARDIR ?= /var
VARDIR ?= $(DESTDIR)$(FINALVARDIR)
FINALLOGDIR ?= $(FINALVARDIR)/log
LOGDIR ?= $(DESTDIR)$(FINALLOGDIR)

# Note: this variable gets passed in, as in "make INITSYSTEM=systemd"
INITSYSTEM ?= $(shell $(top_srcdir)/packaging/utils/lswan_detect.sh init)

DOCKER_PLUTONOFORK ?= --nofork

# An attempt is made to automatically figure out where boot/shutdown scripts
# will finally go:  the first directory in INITDDIRS that exists gets them.
# If none of those exists (or INITDDIRS is empty), INITDDIR_DEFAULT gets them.
# With a non-null DESTDIR, INITDDIR_DEFAULT will be used unless one of the
# INITDDIRS directories has been pre-created under DESTDIR.
INITDDIRS ?= /etc/rc.d/init.d /etc/init.d
INITDDIR_DEFAULT ?= /etc/init.d

# We will overwrite INITDDIRS with INC_RCDIRS untill libreswan 3.32
ifdef INC_RCDIRS
INITDDIRS = $(INC_RCDIRS)
$(warning Warning: Overriding INITDDIRS with deprecated variable INC_RCDIRS)
endif
# We will overwrite INITDDIR_DEFAULT with INC_RCDEFAULT untill libreswan 3.32
ifdef INC_RCDEFAULT
INITDDIR_DEFAULT = $(INC_RCDEFAULT)
$(warning Warning: Overriding INITDDIR_DEFAULT with deprecated variable INC_RCDEFAULT)
endif

# INITDDIR is where boot/shutdown scripts go; FINALINITDDIR is where they think
# will finally be (so utils/Makefile can create a symlink in LIBEXECDIR to
# the place where the boot/shutdown script will finally be, rather than
# the place where it is installed).
FINALINITDDIR ?= $(shell for d in $(INITDDIRS) ; \
		do if test -d $(DESTDIR)/$$d ; \
		then echo $$d ; exit 0 ; \
		fi ; done ; echo $(INITDDIR_DEFAULT) )
INITDDIR ?= $(DESTDIR)$(FINALINITDDIR)

# PYTHON_BINARY is used for python scripts shebang
PYTHON_BINARY ?= /usr/bin/python3

# SHELL_BINARY is used for sh scripts shebang
SHELL_BINARY ?= /bin/sh

# used by _stackmanager
#
# What command to use to load the modules. openwrt does not have modprobe
# Using -b enables blacklisting - this is needed for some known bad
# versions of crypto acceleration modules.
MODPROBEBIN ?= modprobe
MODPROBEARGS ?= --quiet --use-blacklist

### misc installation stuff

# what program to use when installing things
INSTALL ?= install

# flags to the install program, for programs, manpages, and config
# files -b has install make backups (n.b., unlinks original) (let
# install choose the suffix).  Since install procedures will never
# overwrite an existing config file they omit -b.

INSTBINFLAGS ?= -b

# The -m flag is more portable than --mode=.
INSTMANFLAGS ?= -m 0644
INSTCONFFLAGS ?= -m 0644

# flags for bison, overrode in packages/default/foo
BISONOSFLAGS ?=

# must be before all uses; invoking is expensive called once
PKG_CONFIG ?= pkg-config

# XXX: Append NSS_CFLAGS to USERLAND_INCLUDES which puts it after
# -I$(top_srcdir)/include; expanded on every compile so invoke once.
ifndef NSS_CFLAGS
NSS_CFLAGS := $(shell $(PKG_CONFIG) --cflags nss)
endif
USERLAND_INCLUDES += $(NSS_CFLAGS)

# We don't want to link against every library pkg-config --libs nss
# returns
NSS_LDFLAGS ?= -lnss3
NSS_SMIME_LDFLAGS ?= -lsmime3
NSS_UTIL_LDFLAGS ?= -lnssutil3
NSPR_LDFLAGS ?= -lnspr4

# Use local copy of nss function CERT_CompareAVA
# See https://bugzilla.mozilla.org/show_bug.cgi?id=1336487
# This work-around is needed with nss versions before 3.30.
USE_NSS_AVA_COPY ?= false
ifeq ($(USE_NSS_AVA_COPY),true)
USERLAND_CFLAGS += -DNSS_REQ_AVA_COPY
endif

# Use nss IPsec profile for X509 validation. This is less restrictive
# on EKU's. Enable when using NSS >= 3.41 (or RHEL-7.6 / RHEL-8.0)
# See https://bugzilla.mozilla.org/show_bug.cgi?id=1252891
USE_NSS_IPSEC_PROFILE ?= true
ifeq ($(USE_NSS_IPSEC_PROFILE),true)
USERLAND_CFLAGS += -DNSS_IPSEC_PROFILE
endif

# Use a local copy of xfrm.h. This can be needed on older systems
# that do not ship linux/xfrm.h, or when the shipped version is too
# old. Since we ship some not-yet merged ipsec-next offload code, this
# is currently true for basically all distro's
USE_XFRM_HEADER_COPY ?= true
XFRM_LIFETIME_DEFAULT ?= 30

USE_XFRM_INTERFACE_IFLA_HEADER ?= false

# Some systems have a bogus combination of glibc and kernel-headers which
# causes a conflict in the IPv6 defines. Try enabling this option as a workaround
# when you see errors related to 'struct in6_addr'
USE_GLIBC_KERN_FLIP_HEADERS ?= false

# When compiling on a system where unbound is missing the required unbound-event.h
# include file, enable this workaround option that will enable an included copy of
# this file as shipped with libreswan. The copy is taken from unbound 1.6.0.
USE_UNBOUND_EVENT_H_COPY ?= false

# Install the portexclude service for policies/portexcludes.conf policies
# Disabled per default for now because it requires python[23]
USE_PORTEXCLUDES ?= false

# The default DNSSEC root key location is set to /var/lib/unbound/root.key
# DEFAULT_DNSSEC_ROOTKEY_FILE=/var/lib/unbound/root.key

# Enable AddressSanitizer - see https://libreswan.org/wiki/Compiling_with_AddressSanitizer
# requires clang or gcc >= 4.8 and libasan. Do not combine with Electric Fence and do not
# run pluto with --leak-detective
# ASAN = -fsanitize=address
ASAN ?=

### misc configuration, included here in hopes that other files will not
### have to be changed for common customizations.

# You can also run this before starting libreswan on glibc systems:
#export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

# look for POD2MAN command
POD2MAN ?= $(shell which pod2man | grep / | head -n1)

## build environment variations
#
# USE_ variables determine if features are compiled into Libreswan.
#       these let you turn on/off specific features
# HAVE_ variables let you tell Libreswan what system related libraries
#       you may or maynot have

# Enable support for DNSSEC. This requires the unbound and ldns libraries.
USE_DNSSEC ?= true

# For systemd start/stop notifications and watchdog feature
# We only enable this by default if used INITSYSTEM is systemd
ifeq ($(INITSYSTEM),systemd)
USE_SYSTEMD_WATCHDOG ?= true
SD_RESTART_TYPE ?= on-failure
SD_PLUTO_OPTIONS ?= --leak-detective
SYSTEMUNITDIR ?= $(shell $(PKG_CONFIG) systemd --variable=systemdsystemunitdir)
SYSTEMTMPFILESDIR ?= $(shell $(PKG_CONFIG) systemd --variable=tmpfilesdir)
UNITDIR ?= $(DESTDIR)$(SYSTEMUNITDIR)
TMPFILESDIR ?= $(DESTDIR)$(SYSTEMTMPFILESDIR)
else
USE_SYSTEMD_WATCHDOG ?= false
endif

# Figure out ipsec.service file Type= option
ifeq ($(USE_SYSTEMD_WATCHDOG),true)
SD_TYPE=notify
SD_WATCHDOGSEC?=200
else
SD_WATCHDOGSEC ?= 0
SD_TYPE=simple
endif

# Build support for integrity check for libreswan on startup
USE_FIPSCHECK ?= false
FIPSPRODUCTCHECK ?= /etc/system-fips

# Enable Labeled IPsec Functionality (requires SElinux)
USE_LABELED_IPSEC ?= false

# Enable seccomp support (whitelist allows syscalls)
USE_SECCOMP ?= false

# Support for Network Manager
USE_NM ?= true

# Include LDAP support (currently used for fetching CRLs)
USE_LDAP ?= false

# Include libcurl support (currently used for fetching CRLs)
USE_LIBCURL ?= true

# Do we want to limit the number of ipsec connections artificially
USE_IPSEC_CONNECTION_LIMIT ?= false
IPSEC_CONNECTION_LIMIT ?= 250

# For Angstrom linux with broken popen() set to true. See bug #1067
HAVE_BROKEN_POPEN ?= false

NONINTCONFIG = oldconfig

-include ${LIBRESWANSRCDIR}/Makefile.ver

# make sure we only run this once per build,  its too expensive to run
# every time Makefile.inc is included
ifndef IPSECVERSION
 ifeq ($(VERSION_ADD_GIT_DIRTY),true)
  ADD_GIT_DIRTY = --add-git-diry
 endif
IPSECVERSION := $(shell ${LIBRESWANSRCDIR}/packaging/utils/setlibreswanversion ${ADD_GIT_DIRTY} ${IPSECBASEVERSION} ${LIBRESWANSRCDIR})
export IPSECVERSION
endif
ifndef IPSECVIDVERSION
# VID is a somewhat shortened version, eg "3.5" or "3.5-xxx"
IPSECVIDVERSION := $(shell echo ${IPSECVERSION} | sed 's/^\([^-]*\)-\([^-]*\)-.*/\1-\2/')
export IPSECVIDVERSION
endif

OBJDIRTOP ?= ${LIBRESWANSRCDIR}/${OBJDIR}

#
#  Paranoia says to export these just to sure:
export OBJDIR
export OBJDIRTOP

### paths within the source tree

LIBSWANDIR = ${LIBRESWANSRCDIR}/lib/libswan

# Need to specify absolute paths as 'make' (checks dependencies) and
# 'ld' (does the link) are run from different directories.
LIBRESWANLIB = $(abs_top_builddir)/lib/libswan/libswan.a
LSWTOOLLIB = $(abs_top_builddir)/lib/liblswtool/liblswtool.a
BSDPFKEYLIB = $(abs_top_builddir)/lib/libbsdpfkey/libbsdpfkey.a

# XXX: $(LSWTOOLLIB) has circular references to $(LIBRESWANLIB).
LSWTOOLLIBS = $(LSWTOOLLIB) $(LIBRESWANLIB)

LIBDESSRCDIR = ${LIBRESWANSRCDIR}/linux/crypto/ciphers/des

WHACKLIB = ${OBJDIRTOP}/lib/libwhack/libwhack.a
IPSECCONFLIB = ${OBJDIRTOP}/lib/libipsecconf/libipsecconf.a

# export everything so that scripts can use them.
export LIBSWANDIR LIBRESWANSRCDIR ARCH
export LIBRESWANLIB LSWTOOLLIB
export WHACKLIB IPSECCONFLIB

IPSEC_SECRETS_FILE ?= $(FINALCONFDIR)/ipsec.secrets

# how to do variable substitution in sed-transformed files
TRANSFORM_VARIABLES = sed -e "s:@IPSECVERSION@:$(IPSECVERSION):g" \
			-e "/@${OSDEP}_START@/,/@${OSDEP}_END@/d" \
			-e "s:@OSDEP@:${OSDEP}:g" \
			-e "s:@EXAMPLECONFDIR@:$(EXAMPLECONFDIR):g" \
			-e "s:@FINALCONFDDIR@:$(FINALCONFDDIR):g" \
			-e "s:@FINALCONFDIR@:$(FINALCONFDIR):g" \
			-e "s:@FINALCONFFILE@:$(FINALCONFFILE):g" \
			-e "s:@FINALDOCDIR@:$(FINALDOCDIR):g" \
			-e "s:@FINALEXAMPLECONFDIR@:$(FINALEXAMPLECONFDIR):g" \
			-e "s:@FINALLIBEXECDIR@:$(FINALLIBEXECDIR):g" \
			-e "s:@FINALLOGDIR@:$(FINALLOGDIR):g" \
			-e "s:@FINALINITDDIR@:$(FINALINITDDIR):g" \
			-e "s:@FINALSBINDIR@:$(FINALSBINDIR):g" \
			-e "s:@FINALSYSCONFDIR@:$(FINALSYSCONFDIR):g" \
			-e "s:@FINALVARDIR@:$(FINALVARDIR):g" \
			-e "s:@IPSEC_CONF@:$(FINALCONFFILE):g" \
			-e "s:@IPSEC_CONFDDIR@:$(FINALCONFDDIR):g" \
			-e "s:@IPSEC_RUNDIR@:$(FINALRUNDIR):g" \
			-e "s:@IPSEC_NSSDIR@:$(FINALNSSDIR):g" \
			-e "s:@IPSEC_PPKDIR@:$(FINALPPKDIR):g" \
			-e "s:@IPSEC_EXECDIR@:$(FINALLIBEXECDIR):g" \
			-e "s:@IPSEC_VARDIR@:$(FINALVARDIR):g" \
			-e "s:@IPSEC_SBINDIR@:$(FINALSBINDIR):g" \
			-e "s:@IPSEC_SECRETS_FILE@:$(IPSEC_SECRETS_FILE):g" \
			-e "s:@MODPROBEBIN@:$(MODPROBEBIN):g" \
			-e "s:@MODPROBEARGS@:$(MODPROBEARGS):g" \
			-e "s:@PYTHON_BINARY@:$(PYTHON_BINARY):g" \
			-e "s:@SHELL_BINARY@:$(SHELL_BINARY):g" \
			-e "s:@USE_DEFAULT_CONNS@:$(USE_DEFAULT_CONNS):g" \
			-e "s:@SD_TYPE@:$(SD_TYPE):g" \
			-e "s:@SD_RESTART_TYPE@:$(SD_RESTART_TYPE):g" \
			-e "s:@SD_PLUTO_OPTIONS@:$(SD_PLUTO_OPTIONS):g" \
			-e "s:@SD_WATCHDOGSEC@:$(SD_WATCHDOGSEC):g" \
			-e "s:@INITSYSTEM@:$(INITSYSTEM):g" \
			-e "s:@DOCKER_PLUTONOFORK@:$(DOCKER_PLUTONOFORK):g" \

# For KVM testing setup
#POOL ?= ${LIBRESWANSRCDIR}/pool
POOL ?= /vol/pool
# support types are fedora and ubuntu
OSTYPE ?= fedora
OSMEDIA ?= http://download.fedoraproject.org/pub/fedora/linux/releases/28/Server/x86_64/os/

# Ubuntu media
# OSTYPE ?= ubuntu
# OSMEDIA ?= http://ftp.ubuntu.com/ubuntu/dists/precise/main/installer-amd64/

# Build/link against the more pedantic ElectricFence memory allocator;
# used when testing.
USE_EFENCE ?= false
ifeq ($(USE_EFENCE),true)
USERLAND_CFLAGS += -DUSE_EFENCE
USERLAND_LDFLAGS += -lefence
endif

ifdef EFENCE
$(error ERROR: EFENCE is replaced by USE_EFENCE)
endif

#
# Configuration options.
#
# Sometimes the make variable is called USE_<feature> and the C macro
# is called HAVE_<feature>, but not always.
#

#
# Kernel support
#
# KLIPS is no longer supported
# These are really set in mk/defaults/*.mk
#
# support Linux kernel's XFRM (aka NETKEY)
USE_XFRM ?= false
# support BSD/KAME kernels (on *BSD and OSX)?
USE_BSDKAME ?= false

USE_XFRM_INTERFACE ?= true

ifeq ($(USE_XFRM),true)
USERLAND_CFLAGS += -DXFRM_SUPPORT
ifeq ($(USE_XFRM_INTERFACE), true)
USERLAND_CFLAGS += -DUSE_XFRM_INTERFACE
endif
endif

ifeq ($(USE_BSDKAME),true)
USE_XFRM ?= false
USERLAND_CFLAGS += -DBSD_KAME
endif

ifeq ($(USE_DNSSEC),true)
USERLAND_CFLAGS += -DUSE_DNSSEC
UNBOUND_LDFLAGS ?= -lunbound -lldns
DEFAULT_DNSSEC_ROOTKEY_FILE ?= "/var/lib/unbound/root.key"
USERLAND_CFLAGS += -DDEFAULT_DNSSEC_ROOTKEY_FILE=\"${DEFAULT_DNSSEC_ROOTKEY_FILE}\"
endif

ifeq ($(USE_FIPSCHECK),true)
USERLAND_CFLAGS += -DFIPS_CHECK
USERLAND_CFLAGS += -DFIPSPRODUCTCHECK=\"${FIPSPRODUCTCHECK}\"
FIPSCHECK_LDFLAGS ?= -lfipscheck
endif

ifeq ($(USE_LABELED_IPSEC),true)
USERLAND_CFLAGS += -DHAVE_LABELED_IPSEC
endif

ifeq ($(USE_SECCOMP),true)
USERLAND_CFLAGS += -DHAVE_SECCOMP
SECCOMP_LDFLAGS = -lseccomp
endif

ifeq ($(USE_LIBCURL),true)
USERLAND_CFLAGS += -DLIBCURL
CURL_LDFLAGS ?= -lcurl
endif

# Build support for the Linux Audit system

USE_LINUX_AUDIT ?= false
ifeq ($(USE_LINUX_AUDIT),true)
USERLAND_CFLAGS += -DUSE_LINUX_AUDIT
LINUX_AUDIT_LDFLAGS ?= -laudit
endif

ifeq ($(USE_SYSTEMD_WATCHDOG),true)
USERLAND_CFLAGS += -DUSE_SYSTEMD_WATCHDOG
SYSTEMD_WATCHDOG_LDFLAGS ?= -lsystemd
endif

ifeq ($(USE_LDAP),true)
USERLAND_CFLAGS += -DLIBLDAP
LDAP_LDFLAGS ?= -lldap -llber
endif

ifeq ($(USE_NM),true)
USERLAND_CFLAGS+=-DHAVE_NM
endif

# Link with -lrt (only for glibc versions before 2.17)
RT_LDFLAGS ?= -lrt

# include PAM support for XAUTH when available on the platform

USE_XAUTHPAM?=true
ifeq ($(USE_XAUTHPAM),true)
USERLAND_CFLAGS += -DXAUTH_HAVE_PAM
XAUTHPAM_LDFLAGS ?= -lpam
endif

#
# Algorithms (encryption, PRF, DH, ....)
#
# See https://tools.ietf.org/html/rfc8247 for what should be enabled
# by default.
#

ALL_ALGS ?= false

USE_3DES ?= true
ifeq ($(USE_3DES),true)
USERLAND_CFLAGS += -DUSE_3DES
endif

USE_AES ?= true
ifeq ($(USE_AES),true)
USERLAND_CFLAGS += -DUSE_AES
endif

USE_CAMELLIA ?= true
ifeq ($(USE_CAMELLIA),true)
USERLAND_CFLAGS += -DUSE_CAMELLIA
endif

USE_CHACHA?=true
ifeq ($(USE_CHACHA),true)
USERLAND_CFLAGS += -DUSE_CHACHA
endif

USE_DH2 ?= false
ifeq ($(USE_DH2),true)
USERLAND_CFLAGS += -DUSE_DH2
endif

USE_DH22 ?= $(ALL_ALGS)
ifeq ($(USE_DH22),true)
USERLAND_CFLAGS += -DUSE_DH22
endif

USE_DH23 ?= $(ALL_ALGS)
ifeq ($(USE_DH23),true)
USERLAND_CFLAGS += -DUSE_DH23
endif

USE_DH24 ?= $(ALL_ALGS)
ifeq ($(USE_DH24),true)
USERLAND_CFLAGS += -DUSE_DH24
endif

USE_DH31 ?= true
ifeq ($(USE_DH31),true)
USERLAND_CFLAGS += -DUSE_DH31
endif

USE_MD5 ?= true
ifeq ($(USE_MD5),true)
USERLAND_CFLAGS += -DUSE_MD5
endif

USE_SHA1 ?= true
ifeq ($(USE_SHA1),true)
USERLAND_CFLAGS += -DUSE_SHA1
endif

USE_SHA2 ?= true
ifeq ($(USE_SHA2),true)
USERLAND_CFLAGS += -DUSE_SHA2
endif

# Used mostly for IoT
USE_PRF_AES_XCBC ?= true
ifeq ($(USE_PRF_AES_XCBC),true)
USERLAND_CFLAGS += -DUSE_PRF_AES_XCBC
endif

ifeq ($(USE_NETKEY),true)
$(error ERROR: Deprecated USE_NETKEY variable set, use USE_XFRM instead)
endif
ifeq ($(USE_KLIPS),true)
$(error ERROR: Deprecated USE_KLIPS variable set, please migrate to USE_XFRM instead)
endif

# Use the NSS Key Derivation Function (KDF) instead of using the NSS
# secure hash functions to build our own PRF. With this enabled,
# libreswan itself no longer needs to be FIPS validated.
#
# Requires NSS >= 3.52
# NSS 3.44 - 3.51 can be used if the following NSS upstream commit
# is applied:
#
# HG changeset patch
# User Robert Relyea <rrelyea@redhat.com>
# Date 1587427096 25200
#      Mon Apr 20 16:58:16 2020 -0700
# Node ID 225bb39eade102eef5f3999eae04a7a16da9b330
# Parent  aae226c20dfd2189fb395f43269fe06cf1fb9cb1
# Bug 1629663 NSS missing IKEv1 Quick Mode KDF prf r=kjacobs

ifdef USE_NSS_PRF
$(error ERROR: Deprecated USE_NSS_PRF variable set, use USE_NSS_KDF instead)
endif

USE_NSS_KDF ?= false
ifeq ($(USE_NSS_KDF),true)
USERLAND_CFLAGS += -DUSE_NSS_KDF
endif

USERLAND_CFLAGS += -DDEFAULT_RUNDIR=\"$(FINALRUNDIR)\"
USERLAND_CFLAGS += -DIPSEC_CONF=\"$(FINALCONFFILE)\"
USERLAND_CFLAGS += -DIPSEC_CONFDDIR=\"$(FINALCONFDDIR)\"
USERLAND_CFLAGS += -DIPSEC_NSSDIR=\"$(FINALNSSDIR)\"
USERLAND_CFLAGS += -DIPSEC_CONFDIR=\"$(FINALCONFDIR)\"
USERLAND_CFLAGS += -DIPSEC_EXECDIR=\"$(FINALLIBEXECDIR)\"
USERLAND_CFLAGS += -DIPSEC_SBINDIR=\"${FINALSBINDIR}\"
USERLAND_CFLAGS += -DIPSEC_VARDIR=\"$(FINALVARDIR)\"
USERLAND_CFLAGS += -DPOLICYGROUPSDIR=\"${FINALCONFDDIR}/policies\"
USERLAND_CFLAGS += -DIPSEC_SECRETS_FILE=\"$(IPSEC_SECRETS_FILE)\"
# Ensure that calls to NSPR's PR_ASSERT() really do abort.  While all
# calls should have been eliminated (replaced by passert()), keep this
# definition just in case.
USERLAND_CFLAGS += -DFORCE_PR_ASSERT

# stick with RETRANSMIT_INTERVAL_DEFAULT as makefile variable name
ifdef RETRANSMIT_INTERVAL_DEFAULT
USERLAND_CFLAGS += -DRETRANSMIT_INTERVAL_DEFAULT_MS="$(RETRANSMIT_INTERVAL_DEFAULT)"
endif

ifeq ($(HAVE_BROKEN_POPEN),true)
USERLAND_CFLAGS += -DHAVE_BROKEN_POPEN
endif

# Do things like create a daemon using the sequence fork()+exit().  If
# you don't have or don't want to use fork() disable this.
USE_FORK ?= true
ifeq ($(USE_FORK),true)
USERLAND_CFLAGS += -DUSE_FORK=1
else
USERLAND_CFLAGS += -DUSE_FORK=0
endif

# Where possible use vfork() instead of fork().  For instance, when
# creating a child process, use the call sequence vfork()+exec().
#
# Systems with nommu, which do not have fork(), should set this.
USE_VFORK ?= false
ifeq ($(USE_VFORK),true)
USERLAND_CFLAGS += -DUSE_VFORK=1
else
USERLAND_CFLAGS += -DUSE_VFORK=0
endif

# Where possible use daemon() instead of fork()+exit() to create a
# daemon (detached) processes.
#
# Some system's don't support daemon() and some systems don't support
# fork().  Since the daemon call can lead to a race it isn't the
# preferred option.
USE_DAEMON ?= false
ifeq ($(USE_DAEMON),true)
USERLAND_CFLAGS += -DUSE_DAEMON=1
else
USERLAND_CFLAGS += -DUSE_DAEMON=0
endif

# OSX, for instance, doesn't have this call.
USE_PTHREAD_SETSCHEDPRIO ?= true
ifeq ($(USE_PTHREAD_SETSCHEDPRIO),true)
USERLAND_CFLAGS += -DUSE_PTHREAD_SETSCHEDPRIO=1
else
USERLAND_CFLAGS += -DUSE_PTHREAD_SETSCHEDPRIO=0
endif

ifeq ($(origin GCC_LINT),undefined)
GCC_LINT = -DGCC_LINT
endif
USERLAND_CFLAGS += $(GCC_LINT)

# This option was disabled at 2020-04-07
# If this is not needed for longer time, it's safe to
# remove this and code it enables.
# Enable ALLOW_MICROSOFT_BAD_PROPOSAL
#USERLAND_CFLAGS += -DALLOW_MICROSOFT_BAD_PROPOSAL

# some systems require -lcrypt when calling crypt() some do not.
CRYPT_LDFLAGS ?= -lcrypt

# Support for LIBCAP-NG to drop unneeded capabilities for the pluto daemon
USE_LIBCAP_NG ?= true
ifeq ($(USE_LIBCAP_NG),true)
USERLAND_CFLAGS += -DHAVE_LIBCAP_NG
LIBCAP_NG_LDFLAGS ?= -lcap-ng
endif

endif
