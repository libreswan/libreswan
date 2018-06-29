USERLAND_CFLAGS += -DTimeZoneOffset=timezone

# This normally comes in via bind9/config.h
# Fixes a warning in lib/libisc/random.c:44
USERLAND_CFLAGS += -DHAVE_SYS_TYPES_H=1
USERLAND_CFLAGS += -DHAVE_UNISTD_H=1

# Not all environments set this? happened on a arm_tools cross compile
USERLAND_CFLAGS += -Dlinux

# udpfromto socket option for Linux
USERLAND_CFLAGS += -DHAVE_UDPFROMTO=1
USERLAND_CFLAGS += -DHAVE_IP_PKTINFO=1


KLIPSSRC=${LIBRESWANSRCDIR}/linux/net/ipsec

MODULE_DEF_INCLUDE=${LIBRESWANSRCDIR}/packaging/linus/config-all.h
MODULE_DEFCONFIG?=${KLIPSSRC}/defconfig
MOD24BUILDDIR?=${LIBRESWANSRCDIR}/modobj24
MODBUILDDIR?=${LIBRESWANSRCDIR}/modobj

MODULE_FLAGS:=KLIPSMODULE=true -f ${MODULE_DEFCONFIG}

PORTDEFINE=-DSCANDIR_HAS_CONST

# include KLIPS support
USE_KLIPS?=true

# build modules, etc. for KLIPS.
BUILD_KLIPS?=true
BISONOSFLAGS=-g --verbose

USE_LABELED_IPSEC?=true

# Detect linux variants and releases.

# So that the sub-shell is invoked only once, ":=" is used.  This in
# turn means 'ifndef' is needed as := is unconditional.

ifndef LINUX_VARIANT
  ifneq ($(wildcard /etc/os-release),)
    LINUX_VARIANT:=$(shell sed -n -e 's/^ID=//p' /etc/os-release)
  endif
endif
#(info LINUX_VARIANT=$(LINUX_VARIANT))

ifndef LINUX_VARIANT_VERSION
  ifneq ($(wildcard /etc/os-release),)
    LINUX_VARIANT_VERSION:=$(shell sed -n -e 's/^VERSION_ID=//p' /etc/os-release)
  endif
endif
#(info LINUX_VARIANT_VERSION=$(LINUX_VARIANT_VERSION))

ifeq ($(LINUX_VARIANT),fedora)
  USE_FIPSCHECK?=true
  USE_LINUX_AUDIT?=true
  USE_SECCOMP?=true
  # Assume that fedora 22 (used by test VMs) needs the hack
  ifeq ($(LINUX_VARIANT_VERSION),22)
    USE_GLIBC_KERN_FLIP_HEADERS=true
  endif
endif
#(info USE_GLIBC_KERN_FLIP_HEADERS=$(USE_GLIBC_KERN_FLIP_HEADERS))
