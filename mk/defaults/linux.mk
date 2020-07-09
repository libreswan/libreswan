USE_XFRM = true

USERLAND_CFLAGS += -DTimeZoneOffset=timezone

# Not all environments set this? happened on a arm_tools cross compile
USERLAND_CFLAGS += -Dlinux

PORTDEFINE=-DSCANDIR_HAS_CONST

BISONOSFLAGS=-g --verbose

# Detect linux variants and releases.

# So that the sub-shell is invoked only once, ":=" is used.  This in
# turn means 'ifndef' is needed as := is unconditional.

ifndef LINUX_VARIANT
  ifneq ($(wildcard /etc/os-release),)
    LINUX_VARIANT:=$(shell sed -n -e 's/^ID=//p' /etc/os-release)
    export LINUX_VARIANT
  endif
endif
#(info LINUX_VARIANT=$(LINUX_VARIANT))

ifndef LINUX_VARIANT_VERSION
  ifneq ($(wildcard /etc/os-release),)
    LINUX_VARIANT_VERSION:=$(shell sed -n -e 's/^VERSION_ID=//p' /etc/os-release)
    export LINUX_VARIANT_VERSION
  endif
endif
#(info LINUX_VARIANT_VERSION=$(LINUX_VARIANT_VERSION))

ifeq ($(LINUX_VARIANT),fedora)
  USE_LINUX_AUDIT?=true
  USE_SECCOMP?=true
  USE_LABELED_IPSEC?=true
  # Assume that fedora 22 (used by test VMs) needs the hack
  ifeq ($(LINUX_VARIANT_VERSION),22)
    USE_GLIBC_KERN_FLIP_HEADERS=true
  endif
endif
#(info USE_GLIBC_KERN_FLIP_HEADERS=$(USE_GLIBC_KERN_FLIP_HEADERS))
