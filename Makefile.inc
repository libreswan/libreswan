# Libreswan pathnames and other master configuration
# Copyright (C) 2001, 2002  Henry Spencer.
# Copyright (C) 2003-2006   Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#
#  If there is a "local" makfile include it, else ignore:
-include ${LIBRESWANSRCDIR}/Makefile.inc.local


# Variables in this file with names starting with INC_ are not for use
# by Makefiles which include it; they are subject to change without warning.
#
# "Final" and "finally" refer to where the files will end up on the
# running IPsec system, as opposed to where they get installed by our
# Makefiles.  (The two are different for cross-compiles and the like,
# where our Makefiles are not the end of the installation process.)
# Paths with FINAL in their names are the only ones that the installed
# software itself depends on.  (Very few things should know about the
# FINAL paths; think twice and consult Henry before making something new
# depend on them.)  All other paths are install targets.
# See also DESTDIR, below.



### boilerplate, do not change, various scripts use extended BASH syntax!
SHELL=/bin/bash
export SHELL

.PHONY:	programs man config checkprograms clean

# location of shell, practicall always /bin/sh, but can be /usr/bin/sh on Fedora/RHEL
BINSH=/bin/sh

# supply kernel-configuration ARCH defaults
ifeq ($(ARCH),)
ARCH := $(shell uname -m)
endif
# always sanitize $(ARCH)
ARCH := $(shell echo $(ARCH) | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/ -e 's/ //g')

ifeq ($(OSDEP),)
OSDEP:=$(shell uname -s | tr 'A-Z' 'a-z')
endif

### install pathnames

# DESTDIR can be used to supply a prefix to all install targets.
# (Note that "final" pathnames, signifying where files will eventually
# reside rather than where install puts them, are exempt from this.)
# The prefixing is done in this file, so as to have central control over
# it; DESTDIR itself should never appear in any other Makefile.
DESTDIR?=

# "local" part of tree, used in building other pathnames
INC_USRLOCAL=/usr/local

# PUBDIR is where the "ipsec" command goes; beware, many things define PATH
# settings which are assumed to include it (or at least, to include *some*
# copy of the "ipsec" command).
PUBDIR=$(DESTDIR)$(INC_USRLOCAL)/sbin

# BINDIR is where sub-commands get put, FINALBINDIR is where the "ipsec"
# command will look for them when it is run. Also called LIBEXECDIR.
FINALLIBEXECDIR?=$(INC_USRLOCAL)/libexec/ipsec
LIBEXECDIR=$(DESTDIR)$(FINALBINDIR)
FINALLIBDIR?=$(INC_USRLOCAL)/libexec/ipsec
LIBDIR=$(DESTDIR)$(FINALLIBDIR)

FINALBINDIR=${FINALLIBEXECDIR}
BINDIR=${LIBEXECDIR}


# SBINDIR is where the user interface command goes.
FINALSBINDIR?=$(INC_USRLOCAL)/sbin
SBINDIR=$(DESTDIR)$(FINALSBINDIR)



# where the appropriate manpage tree is located
# location within INC_USRLOCAL
INC_MANDIR=man
# the full pathname
MANTREE=$(DESTDIR)$(INC_USRLOCAL)/$(INC_MANDIR)
# all relevant subdirectories of MANTREE
MANPLACES=man3 man5 man8

# where configuration files go
FINALSYSCONFDIR?=/etc

# final configuration file
FINALCONFFILE?=$(FINALSYSCONFDIR)/ipsec.conf
CONFFILE?=$(DESTDIR)$(FINALCONFFILE)

FINALCONFDIR?=$(FINALSYSCONFDIR)

CONFDIR?=$(DESTDIR)$(FINALCONFDIR)
SYSCONFDIR?=$(DESTDIR)$(FINALSYSCONFDIR)

FINALCONFDDIR?=${FINALCONFDIR}/ipsec.d
CONFDDIR?=$(DESTDIR)$(FINALCONFDDIR)

# sample configuration files go into
INC_DOCDIR?=share/doc
FINALEXAMPLECONFDIR?=${INC_USRLOCAL}/${INC_DOCDIR}/libreswan
EXAMPLECONFDIR?=${DESTDIR}${FINALEXAMPLECONFDIR}

FINALDOCDIR?=${INC_USRLOCAL}/${INC_DOCDIR}/libreswan
DOCDIR=${DESTDIR}${FINALDOCDIR}

# where per-conn pluto logs go
FINALVARDIR?=/var
VARDIR?=${DESTDIR}${FINALVARDIR}
FINALLOGDIR?=${FINALVARDIR}/log
LOGDIR?=${DESTDIR}${FINALLOGDIR}


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
MODPROBE?=modprobe -q

### misc installation stuff

# what program to use when installing things
INSTALL=install

# flags to the install program, for programs, manpages, and config files
# -b has install make backups (n.b., unlinks original), --suffix controls
# how backup names are composed.
# Note that the install procedures will never overwrite an existing config
# file, which is why -b is not specified for them.
INSTBINFLAGS=-b --suffix=.old
INSTSUIDFLAGS=--mode=u+rxs,g+rx,o+rx --group=root -b --suffix=.old
#INSTMANFLAGS="-m 644"
INSTCONFFLAGS=
# For OSX use
#INSTBINFLAGS=-b -B .old
#INSTSUIDFLAGS=--mode=u+rxs,g+rx,o+rx --group=root -b -B .old

# flags for bison, overrode in packages/default/foo
BISONOSFLAGS=

NSSFLAGS?=$(shell pkg-config --cflags nss)
NSSLIBS?=$(shell pkg-config --libs nss)

ifeq ($(ARCH),i686)
GCCM?=-m32
endif
ifeq ($(ARCH),x86_64)
GCCM?=-m64
endif

GCC_LINT ?= -DGCC_LINT

### misc configuration, included here in hopes that other files will not
### have to be changed for common customizations.

# extra compile flags, for userland and kernel stuff, e.g. -g for debug info
# you can add to this in the defaults file using +=
# -DGCC_LINT uses gcc-specific declarations to improve compile-time diagnostics.
# -DCOMPILER_HAS_NO_PRINTF_LIKE if your old compiler gives you errors with
# PRINTF_LIKE(x)
#
# Warning: Using -O3 is known to cause problems with the NSS code, see
#          https://bugzilla.redhat.com/show_bug.cgi?id=884710
#
# Example for a cross compile:
# USERCOMPILE?=-g ${PORTDEFINE} -I/usr/local/arm_tools/arm-elf/inc -L/usr/local/arm_tools/lib/gcc-lib
# USERCOMPILE?=-g -O2 ${WERROR} $(GCC_LINT)
USERCOMPILE?=-g -O2 ${GCCM} ${WERROR} $(GCC_LINT) -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4  -mtune=generic -fno-strict-aliasing -fPIE -DPIE  -Wall -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wbad-function-cast

KLIPSCOMPILE=-O2 -DCONFIG_KLIPS_ALG -DDISABLE_UDP_CHECKSUM
# Additional debugging for developers (warning: can crash libreswan!)
#USERCOMPILE?=-g -DLEAK_DETECTIVE -lefence
# You can also run this before starting libreswan on glibc systems:
#export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

# extra link flags
USERLINK?=-Wl,-z,relro
# on fedora/rhel
#USERLINK=-g -pie

PORTINCLUDE?=

# command used to link/copy KLIPS into kernel source tree
# There are good reasons why this is "ln -s"; only people like distribution
# builders should ever change it.
KLIPSLINK=ln -s -f

# extra options for use in kernel build
KERNMAKEOPTS=

# kernel Makefile targets to be done before build
# Can be overridden if you are *sure* your kernel doesn't need them.  (2.2.xx
# and later reportedly do not.)
KERNDEP=dep
KERNCLEAN=clean

# kernel make name:  zImage for 2.0.xx, bzImage for 2.2.xx and later, and
# boot on non-x86s (what ever happened to standards?)
INC_B=$(shell test -d $(DIRIN22) && echo b)
KERNEL=$(shell if expr " `uname -m`" : ' i.86' >/dev/null ; \
	then echo $(INC_B)zImage ; \
	else echo boot ; \
	fi)

# look for XMLTO command
XMLTO?=$(shell which xmlto | grep / | head -n1)

# look for POD2MAN command
POD2MAN?=$(shell which pod2man | grep / | head -n1)

#
# default number of bits for ipsec newhostkey
#
RSAKEYBITS:=2192

# temporary directory to be used when building RPMs, and where to put the
# resulting RPM tree
RPMKERNDIR := $(shell echo `pwd`/tmp.rpmkernel)
RPMTMPDIR := $(shell echo `pwd`/tmp.rpmbuild)
RPMDEST := $(shell echo `pwd`/rpms)

# Newer versions of RPM do not permit building of packages with the "rpm" 
# command. For RedHat systems with older version of RPM, use:
# RPMBUILD=rpm
# instead.
RPMBUILD=rpmbuild

### paths to resources on the host system
#
# Set this to a RedHat kernel-sources RPM. This normally extracts into
# /usr/src/linux-2.4, but you might have extracted it elsewhere with
# rpm2cpio.
# Note: there is no kernel-source rpm anymore for Fedora. Either run
# rpmbuild -bp on the kernel src.rpm and grab the tree from 
# /usr/src/redhat/BUILD/ or use something like the example below using the
# module directory.
# note: there is now a kernel-devel rpm.
#RH_KERNELSRC?=/usr/src/linux-2.4
RH_KERNELSRC?=/lib/modules/2.6.9-1.681_FC3/build

#RH_KERNELSRC=/c2/kernel/rh/linux-2.4.9-13


## build environment variations
##

#
# USE_ variables determine if features are compiled into Libreswan.
#       these let you turn on/off specific features
# HAVE_ variables let you tell Libreswan what system related libraries
#       you may or maynot have

# Do a new lookup every time a connection is (re)started. This works better
# on hosts with some dyndns service, since DPD will cause a new dns lookup,
# but it could be a potential security issue if receiving spoofed dns.
USE_DYNAMICDNS?=true

# Enable support for DNSSEC. This requires the unbound library
USE_DNSSEC?=true

# Do we want all the configuration files like ipsec.conf and ipsec.secrets
# and any certificates to be in a single directory defined by 
# FINALCONFDDIR?
USE_SINGLE_CONF_DIR?=false

# Build ikeping (a utility for testing IKE daemons) in the distribution
USE_IKEPING?=true

# Build support for KEY RR 
# this will become false in the future, as all OE sites transition to
# using IPSECKEY instead of KEY records.  See references to 'Flag Day'
# Except this to change in Q1 2011
USE_KEYRR?=true

# Build support for Linux 2.4 and 2.6 KLIPS kernel level IPsec support
# for pluto
USE_KLIPS?=true

# Build support for 2.6 KLIPS/MAST variation in pluto
USE_MAST?=true

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

# Build support for sending Libreswan Vendor IDs
USE_VENDORID?=true

# Build aggressive mode authentication system code - both Server and Client.
# This was off by default, since aggressive mode leads to denial of service
# attacks.
USE_AGGRESSIVE?=true

# Build XAUTH authentication system code - both Server and Client.
# XAUTH is tricky, and you can get into security trouble unless you
# do additional configuration - but it is often needed for Cisco interop
USE_XAUTH?=true

# When doing XAUTH, include PAM support when available

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

# Build support for the Linux Audit system
ifeq ($(OSDEP),linux)
USE_LINUX_AUDIT?=false
endif

# Enable Labeled IPSec Functionality (requires SElinux)
USE_LABELED_IPSEC?=false

# Support for LIBCAP-NG to drop unneeded capabilities for the pluto daemon
USE_LIBCAP_NG?=true

# Support for Network Manager
USE_NM?=true

# Support for MODP groups described in RFC 5114
USE_MODP_RFC5114?=true

# whether to support NAT Traversal (aka NAT-T)
USE_NAT_TRAVERSAL?=true

# where to support NAT-T in transport mode (needed for Win2K NAT-T Interop)
USE_NAT_TRAVERSAL_TRANSPORT_MODE?=true

# Include LDAP support (currently used for fetching CRLs)
USE_LDAP?=false

# Include libcurl support (currently used for fetching CRLs)
USE_LIBCURL?=true

# should we include all manner of known to be broken/weak?
# use this only if you are building some kind of a testing
# device. Normal use does not need any of this.
USE_WEAKSTUFF?=false

# Build algorithms that don't even encrypt (also must set WEAKSTUFF)
# unless you are doing negative testing, turning this on is foolish.
USE_NOCRYPTO?=false

# should we include additional (strong) algorithms?  It adds a measureable
# amount of code space to pluto, and many of the algorithms have not had
# the same scrutiny that AES and 3DES have received, but offers possibilities 
# of switching away from AES/3DES quickly. 
USE_EXTRACRYPTO?=false

# Do we want to limit the number of ipsec connections artificially
USE_IPSEC_CONNECTION_LIMIT?=false
IPSEC_CONNECTION_LIMIT?=250

# Do we have an external stats daemon we can push state changes to?
# Currently hardcoded to /bin/libreswan-statsd
HAVE_STATSD?=false

# Do we have Openssl libraries available for BIGNUM support?
# Required of HAVE_OCF support
HAVE_OPENSSL?=false

# Userland (IKE) Open Cryptographic Framework support (hw crypto offload)
# For Kernel level OCF support, enable CONFIG_KLIPS_OCF on a kernel that
# has support for OCF (inline or module)
# Only enable this when compiling for embedded systems with very limited CPU
# power, and only if there is actually some hardware accelerator present
# for which there is an OCF kernel driver available.
HAVE_OCF?=false

ifeq ($(HAVE_OCF),true)
HAVE_OPENSSL=true
endif

# Whether or not to include TaProoM (TCL Pluto Mix) into pluto.
# you need at least swig 1.3.24, as well as tcl libraries and includes
USE_TAPROOM?=false

# Whether to use LEAK_DETECTIVE to find memory leaks.
# disabled for now as it causes some pfree()s due to bad code
USE_LEAK_DETECTIVE?=false

# Use dmalloc. Requires USE_LEAK_DETECTIVE
USE_DMALLOC?=false
ifeq ($(USE_DMALLOC),true)
USE_LEAK_DETECTIVE=true
endif

# For Angstrom linux with broken popen() set to true. See bug #1067
HAVE_BROKEN_POPEN?=false

# For systems with no fork (uclibc nommu)
HAVE_NO_FORK?=false

NONINTCONFIG=oldconfig

# Should we build with object directories?
# (not really a code option, but a build option)
# by default we will start using object directories.
ifeq ($(USE_OBJDIR),)
USE_OBJDIR?=true
endif

-include ${LIBRESWANSRCDIR}/Makefile.ver

# make sure we only run this once per build,  its too expensive to run
# every time Makefile.inc is included
ifndef IPSECVERSION
IPSECVERSION:=$(shell ${LIBRESWANSRCDIR}/packaging/utils/setlibreswanversion ${IPSECBASEVERSION} ${LIBRESWANSRCDIR})
export IPSECVERSION
endif

# include OSDEP/ARCH specific makefiles, if any.
# OSDEP=linux,bsd,cygwin,darwin
# 
# but, BUILDENV could be mingw32-linux, darwin, or mingw32, etc..
ifeq ($(BUILDENV),)
BUILDENV=$(shell uname -s | tr 'A-Z' 'a-z' | sed -e 's/\(.*\)-.*/\1/')
endif
export BUILDENV
export OSDEP
include ${LIBRESWANSRCDIR}/packaging/defaults/${BUILDENV}
-include ${LIBRESWANSRCDIR}/packaging/defaults/${BUILDENV}.${ARCH}

# On MAC OSX , we have to use YACC and not BISON. And use different backup
# file suffix.
ifeq ($(BUILDENV),"darwin")
USE_YACC?=true
INSTBINFLAGS=-D -b -B .old
INSTSUIDFLAGS=--mode=u+rxs,g+rx,o+rx --group=root -b -B .old
endif

ifeq ($(USE_OBJDIR),true)
OBJDIR?=OBJ.${BUILDENV}.${ARCH}
OBJDIRTOP?=${LIBRESWANSRCDIR}/${OBJDIR}
else
# where to place the object files which are built 
OBJDIR?=.
OBJDIRTOP?=${LIBRESWANSRCDIR}
endif

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
PLUTOLIB=${OBJDIRTOP}/lib/libpluto/libpluto.a
LSWLOGLIB=${OBJDIRTOP}/lib/libswan/liblswlog.a

LIBDESSRCDIR=${LIBRESWANSRCDIR}/linux/crypto/ciphers/des
LIBDESLITE:=${OBJDIRTOP}/lib/libcrypto/libdes/libdes.a
LIBLSWCRYPTO=${OBJDIRTOP}/lib/libcrypto/liblswcrypto/liblswcrypto.a
LIBAES=${OBJDIRTOP}/lib/libcrypto/libaes/libaes.a
LIBMD5=${OBJDIRTOP}/lib/libcrypto/libmd5/libmd5.a
LIBSHA1=${OBJDIRTOP}/lib/libcrypto/libsha1/libsha1.a
LIBBLOWFISH=${OBJDIRTOP}/lib/libcrypto/libblowfish/libblowfish.a
LIBTWOFISH=${OBJDIRTOP}/lib/libcrypto/libtwofish/libtwofish.a
LIBSERPENT=${OBJDIRTOP}/lib/libcrypto/libserpent/libserpent.a
LIBSHA2=${OBJDIRTOP}/lib/libcrypto/libsha2/libsha2.a
CRYPTOLIBS=${LIBAES} ${LIBSHA1} ${LIBMD5} ${LIBDESLITE} ${LIBSHA2}

ifeq ($(USE_EXTRACRYPTO),true)
CRYPTOLIBS+= ${LIBSERPENT} ${LIBTWOFISH} ${LIBBLOWFISH}
endif

CRYPTOLIBS += ${LIBLSWCRYPTO}
ifeq ($(HAVE_OCF),true)
CRYPTOLIBS += -lcrypto
endif

LIBPOLICYDIR=${LIBRESWANSRCDIR}/linux/lib/libipsecpolicy
POLICYLIB=${OBJDIRTOP}/lib/libipsecpolicy/libipsecpolicy.a

WHACKLIB=${OBJDIRTOP}/lib/libwhack/libwhack.a
IPSECCONFLIB=${OBJDIRTOP}/lib/libipsecconf/libipsecconf.a

# export everything so that scripts can use them.
export LIBSWANDIR LIBRESWANSRCDIR ARCH PORTINCLUDE 
export LIBRESWANLIB LSWLOGLIB PLUTOLIB 
export LIBDESSRCDIR LIBDESLITE LIBAES
export LIBMD5 LIBSHA1 LIBBLOWFISH LIBTWOFISH LIBSERPENT
export LIBSHA2 CRYPTOLIBS LIBPOLICYDIR POLICYLIB WHACKLIB IPSECCONFLIB
export LIBLSWCRYPTO NSSFLAGS NSSLIBS

#KERNELBUILDMFLAGS=--debug=biv V=1 

# how to do variable substitution in sed-transformed files
TRANSFORM_VARIABLES = sed -e "s:@IPSECVERSION@:$(IPSECVERSION):g" \
			-e "s:@IPSEC_DIR@:$(FINALBINDIR):g" \
			-e "s:@IPSEC_EXECDIR@:$(FINALLIBEXECDIR):g" \
			-e "s:@IPSEC_SBINDIR@:$(FINALSBINDIR):g" \
			-e "s:@IPSEC_LIBDIR@:$(FINALLIBDIR):g" \
			-e "s:@FINALCONFFILE@:$(FINALCONFFILE):g" \
			-e "s:@FINALCONFDIR@:$(FINALCONFDIR):g" \
			-e "s:@FINALSBINDIR@:$(FINALSBINDIR):g" \
			-e "s:@FINALBINDIR@:$(FINALBINDIR):g" \
			-e "s:@FINALLIBEXECDIR@:$(FINALLIBEXECDIR):g" \
			-e "s:@FINALLIBDIR@:$(FINALLIBDIR):g" \
			-e "s:@FINALVARDIR@:$(FINALVARDIR):g" \
			-e "s:@FINALCONFDDIR@:$(FINALCONFDDIR):g" \
			-e "/@${OSDEP}_START@/,/@${OSDEP}_END@/d" \
			-e "s:@EXAMPLECONFDIR@:$(EXAMPLECONFDIR):g" \
			-e "s:@FINALDOCDIR@:$(FINALDOCDIR):g" \
			-e "s:@FINALEXAMPLECONFDIR@:$(FINALEXAMPLECONFDIR):g" \
			-e "s:@RSAKEYBITS@:$(RSAKEYBITS):g" \
			-e "s:@USE_DEFAULT_CONNS@:$(USE_DEFAULT_CONNS):g" \
                        -e "s:@MODPROBE@:$(MODPROBE):g" \
                        -e "s:@BINSH@:$(BINSH):g" \
                        -e "s:@FINALSYSCONFDIR@:$(FINALSYSCONFDIR):g" \
                        -e "s:@FINALRCDIR@:$(FINALRCDIR):g" \

# For KVM testing setup
#POOL?=${LIBRESWANSRCDIR}/pool
POOL?=/vol/pool
# support types are fedora and ubuntu
OSTYPE?=fedora
#OSMEDIA?=http://fedora.mirror.nexicom.net/linux/releases/17/Fedora/x86_64/os/
OSMEDIA?=http://76.10.157.69/linux/releases/17/Fedora/x86_64/os

# Ubuntu media
# OSTYPE?=ubuntu
# OSMEDIA?=http://ftp.ubuntu.com/ubuntu/dists/precise/main/installer-amd64/



# for emacs
#
# Local Variables: ;;;
# mode: makefile ;;;
# End Variables: ;;;
#

