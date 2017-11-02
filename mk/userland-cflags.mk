# Userland CFLAG configuration, for libreswan
#
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.org>
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

# -D... goes in here
USERLAND_CFLAGS=-std=gnu99

# If you want or need to override the default detected arch
# GCCM=-m32
# GCCM=-mx32
# GCCM=-m64
# USERLAND_CFLAGS+=$(GCCM)

ifeq ($(origin DEBUG_CFLAGS),undefined)
DEBUG_CFLAGS=-g
endif
USERLAND_CFLAGS+=$(DEBUG_CFLAGS)

ifeq ($(origin OPTIMIZE_CFLAGS),undefined)
# _FORTIFY_SOURCE requires at least -O.  Gentoo, pre-defines
# _FORTIFY_SOURCE (to what? who knows!); force it to our preferred
# value.
OPTIMIZE_CFLAGS=-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif
USERLAND_CFLAGS+=$(OPTIMIZE_CFLAGS)

# Dumping ground for an arbitrary set of flags.  Should probably be
# separated out.
ifeq ($(origin USERCOMPILE),undefined)
USERCOMPILE= -fstack-protector-all -fno-strict-aliasing -fPIE -DPIE
endif
USERLAND_CFLAGS+=$(USERCOMPILE)

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

ifeq ($(USE_KLIPS),true)
USERLAND_CFLAGS+=-DKLIPS
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

ifeq ($(USE_LINUX_AUDIT),true)
USERLAND_CFLAGS+=-DUSE_LINUX_AUDIT
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

# if we use pam for password checking then add it too
ifeq ($(USE_XAUTHPAM),true)
USERLAND_CFLAGS += -DXAUTH_HAVE_PAM
XAUTHPAM_LDFLAGS ?= -lpam
endif

ifeq ($(USE_SAREF_KERNEL),true)
USERLAND_CFLAGS+=-DSAREF_SUPPORTED
endif

USERLAND_CFLAGS+=-DUSE_MD5
USERLAND_CFLAGS+=-DUSE_SHA2
USERLAND_CFLAGS+=-DUSE_SHA1
USERLAND_CFLAGS+=-DUSE_AES
ifeq ($(USE_3DES),true)
USERLAND_CFLAGS+=-DUSE_3DES
endif
ifeq ($(USE_DH22),true)
USERLAND_CFLAGS+=-DUSE_DH22
endif
ifeq ($(USE_CAMELLIA),true)
USERLAND_CFLAGS+=-DUSE_CAMELLIA
endif
ifeq ($(USE_SERPENT),true)
USERLAND_CFLAGS+=-DUSE_SERPENT
LIBSERPENT=${OBJDIRTOP}/lib/libcrypto/libserpent/libserpent.a
endif
ifeq ($(USE_TWOFISH),true)
USERLAND_CFLAGS+=-DUSE_TWOFISH
LIBTWOFISH=${OBJDIRTOP}/lib/libcrypto/libtwofish/libtwofish.a
endif
ifeq ($(USE_CAST),true)
USERLAND_CFLAGS+=-DUSE_CAST
endif
ifeq ($(USE_RIPEMD),true)
USERLAND_CFLAGS+=-DUSE_RIPEMD
endif

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

# eventually: -Wshadow -pedantic
ifeq ($(origin WERROR_CFLAGS),undefined)
WERROR_CFLAGS = -Werror
endif
ifeq ($(origin WARNING_CFLAG),undefined)
WARNING_CFLAGS = -Wall -Wextra -Wformat -Wformat-nonliteral -Wformat-security -Wundef -Wmissing-declarations -Wredundant-decls -Wnested-externs
endif
USERLAND_CFLAGS+= $(WERROR_CFLAGS)
USERLAND_CFLAGS+= $(WARNING_CFLAGS)
