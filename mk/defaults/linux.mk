# Detect linux variants and releases.

# So that the sub-shell is invoked only once, ":=" is used.  Because
# there is no conditional version of := (':=' is unconditional), the
# assignment needs to be wrapped in 'ifndef'.

ifndef LINUX_VARIANT
  export LINUX_VARIANT := $(sort $(shell sed -n -e 's/"//g' -e 's/^ID_LIKE=//p' -e 's/^ID=//p' /etc/os-release))
endif

ifndef LINUX_VERSION_CODENAME
  LINUX_VERSION_CODENAME := $(shell sed -n -e 's/^VERSION_CODENAME=//p' /etc/os-release)
endif

ifndef LINUX_VERSION_ID
  LINUX_VERSION_ID = $(shell sed -n -e 's/^VERSION_ID=//p' /etc/os-release)
endif

#(info LINUX_VARIANT=$(LINUX_VARIANT))
#(info LINUX_VERSION_ID=$(LINUX_VERSION_ID))
#(info LINUX_VERSION_CODENAME=$(LINUX_VERSION_CODENAME))

#
# Debian derived
#

ifneq ($(filter debian,$(LINUX_VARIANT)),)
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /usr/share/dns/root.key
  ifeq ($(VERSION_CODENAME),buster) # Debian 10 (Buster); until June 2024
    USE_NSS_KDF ?= false
  endif
  ifeq ($(VERSION_CODENAME),focal)  # Ubuntu 20.04 LTS (Focal Fossa); until April 2025
    USE_NSS_KDF ?= false
  endif
  ifeq ($(VERSION_CODENAME),bionic) # Ubuntu 18.04 LTS (Bionic Beaver); until April 2023
    USE_NSS_KDF ?= false
    USE_XFRM_INTERFACE_IFLA_HEADER ?= true
    USE_NSS_IPSEC_PROFILE ?= false
  endif
endif

#
# Fedora derived
#

ifneq ($(filter fedora,$(LINUX_VARIANT)),)
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /var/lib/unbound/root.key
  USE_LINUX_AUDIT ?= true
  USE_SECCOMP ?= true
  USE_LABELED_IPSEC ?= true
endif

#
# OpenSuSe derived
# https://en.opensuse.org/SDB:SUSE_and_openSUSE_Products_Version_Outputs
#

ifneq ($(filter suse,$(LINUX_VARIANT)),)
  # https://lists.opensuse.org/archives/list/users@lists.opensuse.org/message/HYB6CKB7DPMPAN7BGUC6MRHE6TWZDABI/
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /var/lib/unbound/root.key
endif

#
# Arch Linux derived
#

ifneq ($(filter arch,$(LINUX_VARIANT)),)
  # https://wiki.archlinux.org/title/unbound#Root_hints
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /etc/trusted-key.key
endif

#
# INITSYSTEM
#

ifndef INITSYSTEM
  ifneq ($(and $(wildcard /lib/systemd/systemd),$(wildcard /var/run/systemd)),)
    INITSYSTEM=systemd
  else ifneq ($(and $(wildcard /sbin/start),$(wildcard /etc/redhat-release)),)
    # override for rhel/centos to use sysvinit
    INITSYSTEM=sysvinit
  else ifneq ($(wildcard /sbin/start),)
    INITSYSTEM=upstart
  else ifneq ($(wildcard /sbin/rc-service /usr/sbin/rc-service),)
    # either
    INITSYSTEM=openrc
  else
    INITSYSTEM=sysvinit
  endif
endif

#
# basic stuff (unless overwridden by above)
#

USE_XFRM ?= true
USERLAND_CFLAGS += -DTimeZoneOffset=timezone
USE_DNSSEC ?= true
