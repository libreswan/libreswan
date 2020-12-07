USE_XFRM = true

USERLAND_CFLAGS += -DTimeZoneOffset=timezone

# Not all environments set this? happened on a arm_tools cross compile
USERLAND_CFLAGS += -Dlinux

# Expose pipe2() which is always available on BSD, what else?
USERLAND_CFLAGS += -D_GNU_SOURCE

PORTDEFINE=-DSCANDIR_HAS_CONST

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

ifeq ($(LINUX_VARIANT),debian)
  DEFAULT_DNSSEC_ROOTKEY_FILE?=/usr/share/dns/root.key
  ifndef VERSION_CODENAME
    ifneq ($(wildcard /etc/os-release),)
      VERSION_CODENAME:=$(shell sed -n -e 's/^VERSION_CODENAME=//p' /etc/os-release)
      export VERSION_CODENAME
    endif
  endif

  ifeq ($(VERSION_CODENAME),buster)
    USE_NSS_KDF?=false
  endif

  ifeq ($(VERSION_CODENAME),stretch)
    USE_NSS_KDF?=false
    USE_XFRM_INTERFACE_IFLA_HEADER?=true
    USE_DNSSEC?=false
    USE_DH31?=false
    USE_NSS_IPSEC_PROFILE?=false
    USE_NSS_AVA_COPY?=true
  endif
endif

ifeq ($(LINUX_VARIANT),ubuntu)
  DEFAULT_DNSSEC_ROOTKEY_FILE?=/usr/share/dns/root.key
  VERSION_CODENAME:=$(shell sed -n -e 's/^VERSION_CODENAME=//p' /etc/os-release)

  ifeq ($(VERSION_CODENAME),focal)
    USE_NSS_KDF?=false
  endif

  ifeq ($(VERSION_CODENAME),stretch)
    USE_NSS_KDF?=false
    USE_XFRM_INTERFACE_IFLA_HEADER?=true
    USE_DNSSEC?=false
    USE_DH31?=false
    USE_NSS_IPSEC_PROFILE?=false
    USE_NSS_AVA_COPY?=true
  endif

  ifeq ($(VERSION_CODENAME),cosmic)
    USE_NSS_KDF?=false
    USE_XFRM_INTERFACE_IFLA_HEADER?=true
    USE_NSS_IPSEC_PROFILE?=false
  endif

  ifeq ($(VERSION_CODENAME),bionic)
    USE_NSS_KDF?=false
    USE_XFRM_INTERFACE_IFLA_HEADER?=true
    USE_NSS_IPSEC_PROFILE?=false
  endif

  ifeq ($(VERSION_CODENAME),xenial)
    USE_NSS_KDF?=false
    USE_XFRM_INTERFACE?=false
    USE_DNSSEC?=false
    USE_DH31?=false
    USE_NSS_IPSEC_PROFILE?=false
    USE_NSS_AVA_COPY?=true
    WERROR_CFLAGS=-Werror -Wno-missing-field-initializers -Wno-error=address
    USE_GLIBC_KERN_FLIP_HEADERS?=true
  endif
endif

ifeq ($(LINUX_VARIANT),fedora)
  USE_LINUX_AUDIT?=true
  USE_SECCOMP?=true
  USE_LABELED_IPSEC?=true

  ifeq ($(LINUX_VARIANT_VERSION),30)
    USE_NSS_KDF?=false
  endif

  ifeq ($(LINUX_VARIANT_VERSION),29)
    USE_NSS_KDF?=false
  endif

  ifeq ($(LINUX_VARIANT_VERSION),28)
    USE_NSS_KDF?=false
  endif

  # Assume that fedora 22 (used by test VMs) needs the hack
  ifeq ($(LINUX_VARIANT_VERSION),22)
    USE_GLIBC_KERN_FLIP_HEADERS=true
  endif

endif
#(info USE_GLIBC_KERN_FLIP_HEADERS=$(USE_GLIBC_KERN_FLIP_HEADERS))


#
# INITSYSTEM
#

ifndef INITSYSTEM
  ifeq ($(shell test -r /proc/1/comm && cat /proc/1/comm),systemd)
    #  works for systemd, not upstart?
    INITSYSTEM=systemd
  else ifneq ($(and $(wildcard /lib/systemd/systemd),$(wildcard /var/run/systemd)),)
    INITSYSTEM=systemd
  else ifneq ($(and $(wildcard /sbin/start),$(wildcard /etc/redhat-release)),)
    # override for rhel/centos to use sysvinit
    INITSYSTEM=sysvinit
  else ifneq ($(wildcard /sbin/start),)
    INITSYSTEM=upstart
  else ifneq ($(or $(wildcard /sbin/rc-service),$(wildcard /usr/sbin/rc-service)),)
    INITSYSTEM=openrc
  else
    INITSYSTEM=sysvinit
  endif
endif
