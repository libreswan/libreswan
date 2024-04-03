# Libreswan configuration
#
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012-2020 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015,2017-2018 Andrew Cagney
# Copyright (C) 2015-2023 Tuomo Soini <tis@foobar.fi>
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

#
# Configuration options.
#
# Sometimes the make variable is called USE_<feature> and the C macro
# is called HAVE_<feature>, but not always.
#
# USE_  assume a package and enable corresponding feature
#
#       For instance USE_SECCOMP assumes the seccomp library and
#       enables the seccomp code.
#
# HAVE_ variables let you tell Libreswan what system related libraries
#       you may or maynot have

# A Makefile wanting to test variables defined below has two choices:
#
# - include config.mk early and use GNU-make's 'ifeq' statement
#
# - include config.mk late, and use $(call if-enabled,VARIABLE,result)
#

if-enabled = $(if $(filter true, $($(strip $(1)))),$(2),$(3))


# TODO: Some creative ifeq ($(OSDEP,xxx) to automatically determine
# where we are building on and disable things

#  Doc:		man make
#  Doc:		http://www.gnu.org/software/make/manual/make.html

# Include any local Makefile.inc.local; local.mk is a wrapper
# that deals with multiple include issues.
include ${LIBRESWANSRCDIR}/mk/local.mk

# Pull in the target/build/host description and get a definition of
# OBJDIR, OSDEP, et.al.
include ${LIBRESWANSRCDIR}/mk/objdir.mk

# Pull in OSDEP specific makefile stub.
#
# Don't try to deal with OS family variants (debian vs fedora vs ...)
# needing different build options (e.g., auditing, fips).  Instead,
# put all that code in the OS family $(OSDEP).mk file - the logic ends
# up being a horrible mess so hopefully that helps to keep the mess
# within the family.
#
# Using the "build" machine to select "target" configuration options
# is, to say the least, a little weird.  It's "historic".
include ${LIBRESWANSRCDIR}/mk/defaults/${OSDEP}.mk

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
# Error out on deprecated since 5.0 config variables.
#
ifdef HAVE_IPTABLES
$(error ERROR: Deprecated HAVE_IPTABLES variable set, use USE_IPTABLES instead)
endif

ifdef HAVE_NFTABLES
$(error ERROR: Deprecated HAVE_NFTABLES variable set, use USE_NFTABLES instead)
endif

#
# Error out on deprecated since 4.0 config variables.
#
ifdef BINDIR
$(error ERROR: Deprecated BINDIR variable set, use LIBEXECDIR instead)
endif

ifdef PUBDIR
$(error ERROR: Deprecated PUBDIR variable is set, use SBINDIR instead)
endif

ifdef EFENCE
$(error ERROR: Deprecated EFENCE variable is set, use USE_EFENCE instead)
endif

ifdef INC_USRLOCAL
$(error ERROR: Deprecated INC_USRLOCAL variable is set, use PREFIX instead)
endif

ifdef MANTREE
$(error ERROR: Deprecated MANTREE variable is set, use MANDIR instead)
endif

ifdef USE_XAUTHPAM
$(error ERROR: Deprecated USE_XAUTHPAM variable is set, use USE_AUTHPAM instead)
endif

ifdef USE_NETKEY
$(error ERROR: Deprecated USE_NETKEY variable is set, use USE_XFRM instead)
endif

ifdef USE_KLIPS
$(error ERROR: Deprecated USE_KLIPS variable is set, migrate to use USE_XFRM instead)
endif

ifdef INC_MANDIR
$(error ERROR: Deprecated INC_MANDIR variable is set, use MANDIR instead)
endif

ifdef INC_DOCDIR
$(error ERROR: Deprecated INC_DOCDIR variable is set, use EXAMPLE_IPSEC_SYSCONFDIR instead)
endif

ifdef INC_RCDIRS
$(error ERROR: Deprecated variable INC_RCDIRS is set, use INIT_D_DIR instead
endif

ifdef INC_RCDEFAULT
$(error ERROR: Deprecated variable INC_RCDEFAULT is set, use INIT_D_DIR instead)
endif

ifdef FINALLIBEXECDIR
$(error ERROR: deprecated variable FINALLIBEXECDIR is set, use LIBEXECDIR instead)
endif

ifdef FINALMANDIR
$(error ERROR: deprecated variable FINALMANDIR is set, use MANDIR instead)
endif

ifdef FINALCONFFILE
$(error ERROR: deprecated variable FINALCONFFILE is set, use IPSEC_CONF instead)
endif

ifdef CONFFILE
$(error ERROR: deprecated variable CONFFILE is set, use IPSEC_CONF instead)
endif

ifdef IPSEC_CONF
$(error ERROR: deprecated variable IPSEC_CONF is set, use IPSEC_CONF instead)
endif

ifdef IPSEC_SECRETS_FILE
$(error ERROR: deprecated variable IPSEC_SECRETS_FILE is set, use IPSEC_SECRETS instead)
endif

ifdef CONFDDIR
$(error ERROR: deprecated variable CONFDDIR is set, use IPSEC_CONFDDIR instead)
endif

ifdef FINALCONFDDIR
$(error ERROR: deprecated variable FINALCONFDDIR is set, use IPSEC_CONFDDIR instead)
endif

ifdef EXAMPLECONFDDIR
$(error ERROR: deprecated variable EXAMPLECONFDDIR is set, use EXAMPLE_IPSEC_CONFDDIR instead)
endif

ifdef EXAMPLEFINALCONFDDIR
$(error ERROR: deprecated variable EXAMPLEFINALCONFDDIR is set, use EXAMPLE_IPSEC_CONFDDIR instead)
endif

ifdef FINALLOGDIR
$(error ERROR: deprecated variable FINALLOGDIR is set, use LOGDIR instead)
endif

ifdef FINALSBINDIR
$(error ERROR: deprecated variable FINALSBINDIR is set, use SBINDIR instead)
endif

ifdef FINALVARDIR
$(error ERROR: deprecated variable FINALVARDIR is set, use VARDIR instead)
endif

ifdef FINALPPKDIR
$(error ERROR: deprecated variable FINALPPKDIR is set)
endif

ifdef PPKDIR
$(error ERROR: deprecated variable PPKDIR is set)
endif

ifdef FINALSYSCONFDIR
$(error ERROR: deprecated variable FINALSYSCONFDIR is set, use SYSCONFDIR instead)
endif

ifdef FINALCONFDIR
$(error ERROR: deprecated variable FINALCONFDIR is set, use SYSCONFDIR instead)
endif

ifdef CONFDIR
$(error ERROR: deprecated variable CONFDIR is set, use SYSCONFDIR instead)
endif

ifdef FINALDOCDIR
$(error ERROR: deprecated variable FINALDOCDIR is set, use EXAMPLE_IPSEC_SYSCONFDIR instead)
endif

ifdef DOCDIR
$(error ERROR: deprecated variable DOCDIR is set, use EXAMPLE_IPSEC_SYSCONFDIR instead)
endif

ifdef FINALINITDDIR
$(error ERROR: deprecated variable FINALINITDDIR is set, use INIT_D_DIR instead)
endif

ifdef FINALRUNDIR
$(error ERROR: deprecated variable FINALRUNDIR is set, use RUNDIR instead)
endif

ifdef FINALLOGROTATEDDIR
$(error ERROR: deprecated variable FINALLOGROTATEDDIR is set, use LOGROTATEDDIR instead)
endif

ifdef EXAMPLEFINALLOGROTATEDDIR
$(error ERROR: deprecated variable EXAMPLEFINALLOGROTATEDDIR is set, use EXAMPLE_LOGROTATEDDIR instead)
endif

ifdef FINALPAMCONFDIR
$(error ERROR: deprecated variable FINALPAMCONFDIR is set, use PAMCONFDIR instead)
endif

ifdef EXAMPLEFINALPAMCONFDIR
$(error ERROR: deprecated variable EXAMPLEFINALPAMCONFDIR is set, use EXAMPLE_PAMCONFDIR instead)
endif

#
# Options that really belong in CFLAGS (making for an intuitive way to
# override them).
#
# AUTOCONF dogma is to put debug and optimization options such as the
# DEBUG_CFLAGS, WARNING_CFLAGS and OPTIMIZE_CFLAGS below, in CFLAGS
# making them easy to tweak.  Stuff that shouldn change such as
# include paths are then put elsewhere (such as USERLAND_CFLAGS).
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

# pick up any generated headers
USERLAND_INCLUDES += -I$(builddir)
# pick up libreswan's includes
USERLAND_INCLUDES += -I$(top_srcdir)/include

# Basic linking flags
USERLAND_LDFLAGS += -Wl,--as-needed
USERLINK ?= -Wl,-z,relro,-z,now -pie
USERLAND_LDFLAGS += $(USERLINK)

#
# Enable LTO by default
#
# Should only need USERLAND_CFLAGS+=-flto.  Unfortunately this doesn't
# work on BSD.  Hence the extra knobs to allow developers to play.

USE_LTO ?= false
LTO_CFLAGS ?= -flto
LTO_LDFLAGS ?=
ifeq ($(USE_LTO),true)
USERLAND_CFLAGS += $(LTO_CFLAGS)
USERLAND_LDFLAGS += $(LTO_LDFLAGS)
endif


### install pathnames

# DESTDIR can be used to supply a prefix to all install targets.
# (Note that "final" pathnames, signifying where files will eventually
# reside rather than where install puts them, are exempt from this.)
# The prefixing is done in this file, so as to have central control over
# it; DESTDIR itself should never appear in any other Makefile.
DESTDIR ?=

# "PREFIX" part of tree, used in building other pathnames.
PREFIX ?= /usr/local

# LIBEXECDIR is where sub-commands get put.  the "ipsec" command will
# look for them when it is run.
LIBEXECDIR ?= $(PREFIX)/libexec/ipsec
TRANSFORMS += 's:@@LIBEXECDIR@@:$(LIBEXECDIR):g'
TRANSFORMS += 's:@@IPSEC_EXECDIR@@:$(LIBEXECDIR):g'
USERLAND_CFLAGS += -DIPSEC_EXECDIR=\"$(LIBEXECDIR)\"

# SBINDIR is where the user interface command goes.
SBINDIR ?= $(PREFIX)/sbin
TRANSFORMS += 's:@@SBINDIR@@:$(SBINDIR):g'
USERLAND_CFLAGS += -DIPSEC_SBINDIR=\"$(SBINDIR)\"

# where the appropriate manpage tree is located
MANDIR ?= $(PREFIX)/share/man
TRANSFORMS += 's:@@MANDIR@@:$(MANDIR):'

# where readonly configuration files go
SYSCONFDIR ?= /etc
TRANSFORMS += 's:@@SYSCONFDIR@@:$(SYSCONFDIR):g'

#
# INITSYSTEM
#
# Selects directory under initsystems/.  The below defines where to
# install it (and their examples).
#
# Unlike ifndef INITSYSTEM, $(origin INITSYSTEM) considers
# INITSYSTEM= to be defined.

ifeq ($(origin INITSYSTEM),undefined)
$(error INITSYSTEM not defined)
endif

INSTALL_INITSYSTEM ?= true

# Where the INITSYSTEM=rc.d boot/shutdown scripts and examples go.
# During install the $(DESTDIR) prefix is added.

RC_D_DIR ?= $(SYSCONFDIR)/rc.d
TRANSFORMS += 's:@@RC_D_DIR@@:$(RC_D_DIR):g'

EXAMPLE_RC_D_DIR ?= $(EXAMPLE_IPSEC_SYSCONFDIR)/$(notdir $(RC_D_DIR))
TRANSFORMS += 's:@@EXAMPLE_RC_D_DIR@@:$(EXAMPLE_RC_D_DIR):g'

# Where the INITSYSTEM=init.d scripts and examples go.  During install
# $(DESTDIR) prefix is added.

INIT_D_DIR ?= /etc/init.d
TRANSFORMS += 's:@@INIT_D_DIR@@:$(INIT_D_DIR):g'

EXAMPLE_INIT_D_DIR ?= $(EXAMPLE_IPSEC_SYSCONFDIR)/$(notdir $(INIT_D_DIR))
TRANSFORMS += 's:@@EXAMPLE_INIT_D_DIR@@:$(EXAMPLE_INIT_D_DIR):g'


# run dir - defaults to /run/pluto
# Some older systems might need to set this to /var/run/pluto
RUNDIR ?= /run/pluto
TRANSFORMS += 's:@@RUNDIR@@:$(RUNDIR):g'
USERLAND_CFLAGS += -DIPSEC_RUNDIR=\"$(RUNDIR)\"

# final configuration file
IPSEC_CONF ?= $(SYSCONFDIR)/ipsec.conf
TRANSFORMS += 's:@@IPSEC_CONF@@:$(IPSEC_CONF):g'
USERLAND_CFLAGS += -DIPSEC_CONF=\"$(IPSEC_CONF)\"

# final secrets file
IPSEC_SECRETS ?= $(SYSCONFDIR)/ipsec.secrets
TRANSFORMS += 's:@@IPSEC_SECRETS@@:$(IPSEC_SECRETS):g'
USERLAND_CFLAGS += -DIPSEC_SECRETS=\"$(IPSEC_SECRETS)\"

IPSEC_CONFDDIR ?= $(SYSCONFDIR)/ipsec.d
TRANSFORMS += 's:@@IPSEC_CONFDDIR@@:$(IPSEC_CONFDDIR):g'
USERLAND_CFLAGS += -DIPSEC_CONFDDIR=\"$(IPSEC_CONFDDIR)\"

EXAMPLE_IPSEC_CONFDDIR ?= $(EXAMPLE_IPSEC_SYSCONFDIR)/ipsec.d
TRANSFORMS += 's:@@EXAMPLE_IPSEC_CONFDDIR@@:$(EXAMPLE_IPSEC_CONFDDIR):g'

# libreswan's sample configuration files go into ...
EXAMPLE_IPSEC_SYSCONFDIR ?= $(PREFIX)/share/doc/libreswan
TRANSFORMS += 's:@@EXAMPLE_IPSEC_SYSCONFDIR@@:$(EXAMPLE_IPSEC_SYSCONFDIR):g'

# where per-conn pluto logs go
VARDIR ?= /var
TRANSFORMS += 's:@@VARDIR@@:$(VARDIR):g'
USERLAND_CFLAGS += -DIPSEC_VARDIR=\"$(VARDIR)\"

LOGDIR ?= $(VARDIR)/log
TRANSFORMS += 's:@@LOGDIR@@:$(LOGDIR):g'

# Directory for logrotate config
LOGROTATEDDIR ?= $(SYSCONFDIR)/logrotate.d
TRANSFORMS += 's:@@LOGROTATEDDIR@@:$(LOGROTATEDDIR):g'
EXAMPLE_LOGROTATEDDIR ?= $(EXAMPLE_IPSEC_SYSCONFDIR)/logrotate.d
TRANSFORMS += 's:@@EXAMPLE_LOGROTATEDDIR@@:$(EXAMPLE_LOGROTATEDDIR):g'

# Where nss databases go
NSSDIR ?= $(VARDIR)/lib/ipsec/nss
# RHEL/CentOS <= 8 and Fedora <= 32 uses /etc/ipsec.d
# NSSDIR ?= /etc/ipsec.d
TRANSFORMS += 's:@@IPSEC_NSSDIR@@:$(NSSDIR):g'
USERLAND_CFLAGS += -DIPSEC_NSSDIR=\"$(NSSDIR)\"

# Where NSS programs live (well most of them, fedora hides vfychain,
# see hack in ipsec.in).
ifndef NSS_BINDIR
NSS_BINDIR := $(shell pkg-config --variable prefix nss)/bin
export NSS_BINDIR
endif
TRANSFORMS += 's:@@NSS_BINDIR@@:$(NSS_BINDIR):g'
USERLAND_CFLAGS += -DNSS_BINDIR=\"$(NSS_BINDIR)\"

DOCKER_PLUTONOFORK ?= --nofork

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

# For "make install", should stuff be installed into /etc?  PKGSRC,
# for instance, wants everything copied into examples/ but not
# installed into /etc.
INSTALL_CONFIGS ?= true


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
SSL_LDFLAGS ?= -lssl3

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

# -levent can mean two things?
LIBEVENT_LDFLAGS ?= -levent_core -levent_pthreads

# Install the portexclude service for policies/portexcludes.conf policies
# Disabled per default for now because it requires python[23]
USE_PORTEXCLUDES ?= false

# Enable AddressSanitizer - see https://libreswan.org/wiki/Compiling_with_AddressSanitizer
# requires clang or gcc >= 4.8 and libasan. Do not combine with Electric Fence and do not
# run pluto with --leak-detective
# ASAN = -fsanitize=address
ASAN ?=
USERLAND_LDFLAGS += $(ASAN)

### misc configuration, included here in hopes that other files will not
### have to be changed for common customizations.

# You can also run this before starting libreswan on glibc systems:
#export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

# look for POD2MAN command
POD2MAN ?= $(shell which pod2man | grep / | head -n1)

# Enable or disable support for IKEv1. When disabled, the ike-policy= value
# will be ignored and all IKEv1 packets will be dropped.
USE_IKEv1 ?= true
ifeq ($(USE_IKEv1),true)
USERLAND_CFLAGS += -DUSE_IKEv1
endif

# For systemd start/stop notifications and watchdog feature
# We only enable this by default if used INITSYSTEM is systemd
ifeq ($(INITSYSTEM),systemd)
USE_SYSTEMD_WATCHDOG ?= true
SD_RESTART_TYPE ?= on-failure
SD_PLUTO_OPTIONS ?= --leak-detective
SYSTEMUNITDIR ?= $(shell $(PKG_CONFIG) systemd --variable=systemdsystemunitdir)
SYSTEMTMPFILESDIR ?= $(shell $(PKG_CONFIG) systemd --variable=tmpfilesdir)
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

# For Angstrom linux with broken popen() set to true. See bug #1067
HAVE_BROKEN_POPEN ?= false

NONINTCONFIG = oldconfig

include $(top_srcdir)/mk/version.mk

# Make sure we only run this once per build, its too expensive to run
# every time mk/config.mk is included
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
LSWSDLIB = $(abs_top_builddir)/lib/liblswsd/liblswsd.a

# XXX: $(LSWTOOLLIB) has circular references to $(LIBRESWANLIB).
LSWTOOLLIBS = $(LSWTOOLLIB) $(LIBRESWANLIB)

LIBDESSRCDIR = ${LIBRESWANSRCDIR}/linux/crypto/ciphers/des

WHACKLIB = ${OBJDIRTOP}/lib/libwhack/libwhack.a
IPSECCONFLIB = ${OBJDIRTOP}/lib/libipsecconf/libipsecconf.a

# export everything so that scripts can use them.
export LIBSWANDIR LIBRESWANSRCDIR
export LIBRESWANLIB LSWTOOLLIB
export WHACKLIB IPSECCONFLIB

# how to do variable substitution in sed-transformed files
#
# Most SEDs support -i (in-place) but FreeBSD does not and gets to
# override this with gsed.

SED ?= sed
TRANSFORM_VARIABLES = $(SED) \
			-e "s:@@DOCKER_PLUTONOFORK@@:$(DOCKER_PLUTONOFORK):g" \
			-e "s:@@INITSYSTEM@@:$(INITSYSTEM):g" \
			-e "s:@@IPSECVERSION@@:$(IPSECVERSION):g" \
			-e "s:@@MODPROBEARGS@@:$(MODPROBEARGS):g" \
			-e "s:@@MODPROBEBIN@@:$(MODPROBEBIN):g" \
			-e "s:@@SD_PLUTO_OPTIONS@@:$(SD_PLUTO_OPTIONS):g" \
			-e "s:@@SD_RESTART_TYPE@@:$(SD_RESTART_TYPE):g" \
			-e "s:@@SD_TYPE@@:$(SD_TYPE):g" \
			-e "s:@@SD_WATCHDOGSEC@@:$(SD_WATCHDOGSEC):g" \
			-e "s:@@SHELL_BINARY@@:$(SHELL_BINARY):g" \
			-e "s:@@USE_DEFAULT_CONNS@@:$(USE_DEFAULT_CONNS):g" \
			$(patsubst %, -e %, $(TRANSFORMS))

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

#
# Kernel support
#
# KLIPS is no longer supported
# These are really set in mk/defaults/*.mk
#

# support Linux kernel's XFRM (aka NETKEY)
USE_XFRM ?= false
# support pfkey v2 interface (typically KAME derived)
USE_PFKEYV2 ?= false

ifeq ($(USE_XFRM),true)
USERLAND_CFLAGS += -DKERNEL_XFRM
endif

ifeq ($(USE_PFKEYV2),true)
USERLAND_CFLAGS += -DKERNEL_PFKEYV2
endif

# extra XFRM options

ifeq ($(USE_XFRM),true)
USE_XFRM_INTERFACE ?= true
ifeq ($(USE_XFRM_INTERFACE), true)
USERLAND_CFLAGS += -DUSE_XFRM_INTERFACE
endif
endif

# Use a local copy of xfrm.h. This can be needed on older systems
# that do not ship linux/xfrm.h, or when the shipped version is too
# old. Since we ship some not-yet merged ipsec-next offload code, this
# is currently true for basically all distro's

USE_XFRM_HEADER_COPY ?= false
USE_XFRM_INTERFACE_IFLA_HEADER ?= false

ifeq ($(USE_XFRM),true)
XFRM_LIFETIME_DEFAULT ?= 30
USERLAND_CFLAGS += -DXFRM_LIFETIME_DEFAULT=$(XFRM_LIFETIME_DEFAULT)
endif

# Enable support for DNSSEC. This requires the unbound and ldns
# libraries.  The default DNSSEC root key location must be set in
# default/*.mk; look for auto-trust-anchor-file in unbound.conf.

USE_DNSSEC ?= true
# DEFAULT_DNSSEC_ROOTKEY_FILE=<unspecified>

ifeq ($(USE_DNSSEC),true)
USERLAND_CFLAGS += -DUSE_DNSSEC
UNBOUND_LDFLAGS ?= -lunbound -lldns
ifndef DEFAULT_DNSSEC_ROOTKEY_FILE
$(error DEFAULT_DNSSEC_ROOTKEY_FILE unknown)
endif
USERLAND_CFLAGS += -DDEFAULT_DNSSEC_ROOTKEY_FILE=\"$(DEFAULT_DNSSEC_ROOTKEY_FILE)\"
endif

ifeq ($(USE_LABELED_IPSEC),true)
USERLAND_CFLAGS += -DHAVE_LABELED_IPSEC
endif

ifeq ($(USE_SECCOMP),true)
USERLAND_CFLAGS += -DUSE_SECCOMP
SECCOMP_LDFLAGS = -lseccomp
endif

ifeq ($(USE_LIBCURL),true)
USERLAND_CFLAGS += -DLIBCURL
CURL_LDFLAGS ?= -lcurl
endif

USE_LINUX_AUDIT ?= false
ifeq ($(USE_LINUX_AUDIT),true)
USERLAND_CFLAGS += -DUSE_LINUX_AUDIT
LINUX_AUDIT_LDFLAGS ?= -laudit
endif

ifeq ($(USE_SYSTEMD_WATCHDOG),true)
USERLAND_CFLAGS += -DUSE_SYSTEMD_WATCHDOG
endif

ifeq ($(USE_LDAP),true)
USERLAND_CFLAGS += -DLIBLDAP
LDAP_LDFLAGS ?= -lldap -llber
endif

ifeq ($(USE_NM),true)
USERLAND_CFLAGS+=-DHAVE_NM
endif

#
# Enable Client Address Translation; what ever that is.
#

USE_CAT ?= false

ifeq ($(USE_CAT),true)
USERLAND_CFLAGS += -DUSE_CAT
endif

TRANSFORMS += 's:@@USE_CAT@@:$(USE_CAT):g'

#
# Enable NFLOG; what ever that is.
#

USE_NFLOG ?= false

ifeq ($(USE_NFLOG),true)
USERLAND_CFLAGS += -DUSE_NFLOG
endif

TRANSFORMS += 's:@@USE_NFLOG@@:$(USE_NFLOG):g'

#
# IPTABLES vs NFTABLES
#

USE_IPTABLES ?= false

ifeq ($(USE_IPTABLES),true)
USERLAND_CFLAGS += -DUSE_IPTABLES
endif

TRANSFORMS += 's:@@USE_IPTABLES@@:$(USE_IPTABLES):g'

USE_NFTABLES ?= false

ifeq ($(USE_NFTABLES),true)
USERLAND_CFLAGS += -DUSE_NFTABLES
endif

TRANSFORMS += 's:@@USE_NFTABLES@@:$(USE_NFTABLES):g'

#
# Check for conflicts between NFTABLES, IPTABLES, CAT and 
# NFLOG.
#
# CAT and NFLOG require one of USE_NFTABLES or USE_IPTABLES.  Can't
# have both USE_NFTABLES and USE_IPTABLES.
#
# Do this after all the MAKE variables have been initialized.

ifeq ($(USE_CAT),true)
ifeq ($(USE_NFTABLES),false)
ifeq ($(USE_IPTABLES),false)
$(error ERROR: USE_CAT=true requires either USE_NFTABLES=true or USE_IPTABLES=true)
endif
endif
endif

ifeq ($(USE_NFLOG),true)
ifeq ($(USE_NFTABLES),false)
ifeq ($(USE_IPTABLES),false)
$(error ERROR: USE_NFLOG=true requires either USE_NFTABLES=true or USE_IPTABLES=true)
endif
endif
endif

ifeq ($(USE_NFTABLES),true)
ifeq ($(USE_IPTABLES),true)
$(error ERROR: Both USE_NFTABLES=true and USE_IPTABLES=true are set, you can not set both)
endif
endif

# Link with -lrt (only for glibc versions before 2.17)
RT_LDFLAGS ?= -lrt

# include PAM support for IKEv1 XAUTH and IKE2 pam-authorize when available on the platform
USE_AUTHPAM ?= true
ifeq ($(USE_AUTHPAM),true)
USERLAND_CFLAGS += -DUSE_PAM_AUTH
AUTHPAM_LDFLAGS ?= -lpam
endif

PAMCONFDIR ?= $(SYSCONFDIR)/pam.d
TRANSFORMS += 's:@@PAMCONFDIR@@:$(PAMCONFDIR):g'
EXAMPLE_PAMCONFDIR ?= $(EXAMPLE_IPSEC_SYSCONFDIR)/pam.d
TRANSFORMS += 's:@@EXAMPLEPAMCONFDIR@@:$(EXAMPLE_PAMCONFDIR):g'

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

USE_CHACHA ?= true
ifeq ($(USE_CHACHA),true)
USERLAND_CFLAGS += -DUSE_CHACHA
endif

USE_DH2 ?= $(ALL_ALGS)
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

# Use NSS's FIPS compliant Key Derivation Function (KDF).
#
# With this enabled, libreswan itself no longer needs to be FIPS
# validated.  With this disabled, libreswan will use it's own KDF
# code.
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

USE_NSS_KDF ?= true
ifeq ($(USE_NSS_KDF),true)
USERLAND_CFLAGS += -DUSE_NSS_KDF
endif

USERLAND_CFLAGS += -DIPSEC_SYSCONFDIR=\"$(SYSCONFDIR)\"
USERLAND_CFLAGS += -DPOLICYGROUPSDIR=\"$(IPSEC_CONFDDIR)/policies\"
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

# some systems require -lcrypt when calling crypt() some do not.
CRYPT_LDFLAGS ?= -lcrypt

# Support for LIBCAP-NG to drop unneeded capabilities for the pluto daemon
USE_LIBCAP_NG ?= true
ifeq ($(USE_LIBCAP_NG),true)
USERLAND_CFLAGS += -DHAVE_LIBCAP_NG
LIBCAP_NG_LDFLAGS ?= -lcap-ng
endif

# Support for CISCO adding a second, narrower, child to IKEv1?!?
# probably broken.

USE_CISCO_SPLIT ?= false
ifeq ($(USE_CISCO_SPLIT),true)
USERLAND_CFLAGS += -DUSE_CISCO_SPLIT
endif

endif
