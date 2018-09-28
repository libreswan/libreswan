# Userland CFLAG configuration, for libreswan
#
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2018 Andrew Cagney <cagney@gnu.org>
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

# -D... goes in here
USERLAND_CFLAGS+=-std=gnu99

#
# Options that really belong in CFLAGS (making for an intuitive way to
# override them).
#
# Unfortunately this file is shared with the kernel which seems to
# have its own ideas on CFLAGS.
#

DEBUG_CFLAGS?=-g
USERLAND_CFLAGS+=$(DEBUG_CFLAGS)

# eventually: -Wshadow -pedantic?
WERROR_CFLAGS?=-Werror
USERLAND_CFLAGS+= $(WERROR_CFLAGS)
WARNING_CFLAGS?=-Wall -Wextra -Wformat -Wformat-nonliteral -Wformat-security -Wundef -Wmissing-declarations -Wredundant-decls -Wnested-externs
USERLAND_CFLAGS+= $(WARNING_CFLAGS)

# _FORTIFY_SOURCE requires at least -O.  Gentoo, pre-defines
# _FORTIFY_SOURCE (to what? who knows!); force it to our preferred
# value.
OPTIMIZE_CFLAGS?=-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
USERLAND_CFLAGS+=$(OPTIMIZE_CFLAGS)

# Dumping ground for an arbitrary set of flags.  Should probably be
# separated out.
USERCOMPILE?=-fstack-protector-all -fno-strict-aliasing -fPIE -DPIE
USERLAND_CFLAGS+=$(USERCOMPILE)

# Build/link against the more pedantic ElectricFence memory allocator;
# used when testing.
USE_EFENCE ?= false
ifeq ($(USE_EFENCE),true)
USERLAND_CFLAGS+=-DUSE_EFENCE
EFENCE_LDFLAGS ?= -lefence
endif
ifneq ($(EFENCE),)
$(warning EFENCE=$(EFENCE) replaced by USE_EFENCE=true)
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
# Order these so that the enabled kernel support can fill in defaults
# for rest.  For instance, MAST should enable KLIPS which should enble
# PFKEYv2.  So that Makefile.inc.local can override, the values are
# not forced.  over However don't force

# support BSD/KAME kernels (on *BSD and OSX)?
USE_BSDKAME?=false
ifeq ($(USE_BSDKAME),true)
USE_NETKEY?=false
USE_KLIPS?=false
USE_MAST?=false
endif

# support KLIPS/MAST kernel variation (MAST requires KLIPS)
USE_MAST?=false
ifeq ($(USE_MAST),true)
USE_KLIPS?=true
endif

# support KLIPS kernel module (KLIPS requires PFKEYv2)
USE_KLIPS?=true
ifeq ($(USE_KLIPS),true)
USE_PFKEYv2?=true
endif

# support Linux kernel's NETLINK_XFRM (aka NETKEY) (aka "native",
# "kame"???) (NETLINK does not use PFKEY, but it does share some code.
# True?!?)
USE_NETKEY?=true
ifeq ($(USE_NETKEY),true)
USE_PFKEYv2=true
endif

# above should set these
USE_PFKEYv2?=false

ifeq ($(USE_BSDKAME),true)
USERLAND_CFLAGS += -DBSD_KAME
endif

ifeq ($(USE_MAST),true)
USERLAND_CFLAGS += -DKLIPS_MAST
endif

ifeq ($(USE_KLIPS),true)
USERLAND_CFLAGS+=-DKLIPS
endif

ifeq ($(USE_NETKEY),true)
USERLAND_CFLAGS+=-DNETKEY_SUPPORT
endif

ifeq ($(USE_PFKEYv2),true)
USERLAND_CFLAGS+=-DPFKEY
endif

#

ifeq ($(USE_DNSSEC),true)
USERLAND_CFLAGS+=-DUSE_DNSSEC
UNBOUND_LDFLAGS ?= -lunbound -lldns
DEFAULT_DNSSEC_ROOTKEY_FILE ?= "/var/lib/unbound/root.key"
USERLAND_CFLAGS+=-DDEFAULT_DNSSEC_ROOTKEY_FILE=\"${DEFAULT_DNSSEC_ROOTKEY_FILE}\"
endif

ifeq ($(USE_NIC_OFFLOAD),true)
USERLAND_CFLAGS+= -DUSE_NIC_OFFLOAD
endif

ifeq ($(USE_FIPSCHECK),true)
USERLAND_CFLAGS+=-DFIPS_CHECK
USERLAND_CFLAGS+=-DFIPSPRODUCTCHECK=\"${FIPSPRODUCTCHECK}\"
FIPSCHECK_LDFLAGS ?= -lfipscheck
endif

ifeq ($(USE_LABELED_IPSEC),true)
USERLAND_CFLAGS+=-DHAVE_LABELED_IPSEC
endif

ifeq ($(USE_SECCOMP),true)
USERLAND_CFLAGS+=-DHAVE_SECCOMP
SECCOMP_LDFLAGS=-lseccomp
endif

ifeq ($(USE_LIBCURL),true)
USERLAND_CFLAGS+=-DLIBCURL
CURL_LDFLAGS ?= -lcurl
endif

# Build support for the Linux Audit system

USE_LINUX_AUDIT ?= false
ifeq ($(USE_LINUX_AUDIT),true)
USERLAND_CFLAGS += -DUSE_LINUX_AUDIT
LINUX_AUDIT_LDFLAGS ?= -laudit
endif

ifeq ($(USE_SYSTEMD_WATCHDOG),true)
USERLAND_CFLAGS+=-DUSE_SYSTEMD_WATCHDOG
SYSTEMD_WATCHDOG_LDFLAGS ?= -lsystemd
endif

ifeq ($(USE_LDAP),true)
USERLAND_CFLAGS += -DLIBLDAP
LDAP_LDFLAGS ?= -lldap -llber
endif

ifeq ($(USE_NM),true)
USERLAND_CFLAGS+=-DHAVE_NM
endif

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

USE_3DES?=true
ifeq ($(USE_3DES),true)
USERLAND_CFLAGS+=-DUSE_3DES
endif

USE_AES ?= true
ifeq ($(USE_AES),true)
USERLAND_CFLAGS+=-DUSE_AES
endif

USE_CAST ?= $(ALL_ALGS)
ifeq ($(USE_CAST),true)
USERLAND_CFLAGS += -DUSE_CAST
endif

USE_CAMELLIA ?= true
ifeq ($(USE_CAMELLIA),true)
USERLAND_CFLAGS += -DUSE_CAMELLIA
endif

USE_CHACHA?=true
ifeq ($(USE_CHACHA),true)
USERLAND_CFLAGS+=-DUSE_CHACHA
endif

USE_DH2 ?= true
ifeq ($(USE_DH2),true)
USERLAND_CFLAGS+=-DUSE_DH2
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

USE_RIPEMD ?= $(ALL_ALGS)
ifeq ($(USE_RIPEMD),true)
USERLAND_CFLAGS += -DUSE_RIPEMD
endif

USE_SERPENT?=true
ifeq ($(USE_SERPENT),true)
USERLAND_CFLAGS += -DUSE_SERPENT
LIBSERPENT = ${OBJDIRTOP}/lib/libcrypto/libserpent/libserpent.a
endif

USE_SHA1 ?= true
ifeq ($(USE_SHA1),true)
USERLAND_CFLAGS += -DUSE_SHA1
endif

USE_SHA2 ?= true
ifeq ($(USE_SHA2),true)
USERLAND_CFLAGS += -DUSE_SHA2
endif

USE_TWOFISH?=true
ifeq ($(USE_TWOFISH),true)
USERLAND_CFLAGS += -DUSE_TWOFISH
LIBTWOFISH= ${OBJDIRTOP}/lib/libcrypto/libtwofish/libtwofish.a
endif

USE_XCBC ?= true
ifeq ($(USE_XCBC),true)
USERLAND_CFLAGS += -DUSE_XCBC
endif

#

ifeq ($(USE_SINGLE_CONF_DIR),true)
USERLAND_CFLAGS+=-DSINGLE_CONF_DIR=1
endif

USERLAND_CFLAGS+=-DDEFAULT_RUNDIR=\"$(FINALRUNDIR)\"
USERLAND_CFLAGS+=-DFIPSPRODUCTCHECK=\"${FIPSPRODUCTCHECK}\"
USERLAND_CFLAGS+=-DIPSEC_CONF=\"$(FINALCONFFILE)\"
USERLAND_CFLAGS+=-DIPSEC_CONFDDIR=\"$(FINALCONFDDIR)\"
USERLAND_CFLAGS+=-DIPSEC_NSSDIR=\"$(FINALNSSDIR)\"
USERLAND_CFLAGS+=-DIPSEC_CONFDIR=\"$(FINALCONFDIR)\"
USERLAND_CFLAGS+=-DIPSEC_EXECDIR=\"$(FINALLIBEXECDIR)\"
USERLAND_CFLAGS+=-DIPSEC_SBINDIR=\"${FINALSBINDIR}\"
USERLAND_CFLAGS+=-DIPSEC_VARDIR=\"$(FINALVARDIR)\"
USERLAND_CFLAGS+=-DPOLICYGROUPSDIR=\"${FINALCONFDDIR}/policies\"
USERLAND_CFLAGS+=-DIPSEC_SECRETS_FILE=\"$(IPSEC_SECRETS_FILE)\"
# Ensure that calls to NSPR's PR_ASSERT() really do abort.  While all
# calls should have been eliminated (replaced by passert()), keep this
# definition just in case.
USERLAND_CFLAGS+=-DFORCE_PR_ASSERT

# stick with RETRANSMIT_INTERVAL_DEFAULT as makefile variable name
ifdef RETRANSMIT_INTERVAL_DEFAULT
USERLAND_CFLAGS+=-DRETRANSMIT_INTERVAL_DEFAULT_MS="$(RETRANSMIT_INTERVAL_DEFAULT)"
endif

ifeq ($(HAVE_BROKEN_POPEN),true)
USERLAND_CFLAGS+=-DHAVE_BROKEN_POPEN
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
# Some system's don't suport daemon() and some systems don't support
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
GCC_LINT=-DGCC_LINT
endif
USERLAND_CFLAGS+=$(GCC_LINT)

# Enable ALLOW_MICROSOFT_BAD_PROPOSAL
USERLAND_CFLAGS+=-DALLOW_MICROSOFT_BAD_PROPOSAL

# some systems require -lcrypt when calling crypt() some do not.
CRYPT_LDFLAGS ?= -lcrypt

# Support for LIBCAP-NG to drop unneeded capabilities for the pluto daemon
USE_LIBCAP_NG?=true
ifeq ($(USE_LIBCAP_NG),true)
USERLAND_CFLAGS += -DHAVE_LIBCAP_NG
LIBCAP_NG_LDFLAGS ?= -lcap-ng
endif
