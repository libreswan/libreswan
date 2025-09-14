# Detect linux variants and releases.

# So that the sub-shell is invoked only once, ":=" is used.  Because
# there is no conditional version of := (':=' is unconditional), the
# assignment needs to be wrapped in 'ifndef'.

ifndef LINUX_VARIANT
  # ID+ID_LIKE, for instance:
  #   Debian: ID=debian
  #   Fedora: ID=fedora
  #   Red Hat: ID=redhat ID_LIKE=fedora? => redhat fedora?
  #   Mint: ID=linuxmint ID_LIKE=ubuntu => linuxmint ubuntu
  # $(sort) gets rid of duplicates (needed?)
  export LINUX_VARIANT := $(sort $(shell sed -n -e 's/"//g' -e 's/^ID_LIKE=//p' -e 's/^ID=//p' /etc/os-release))
endif

ifndef LINUX_VERSION_CODENAME
  # VERSION_CODENAME+UBUNTU_CODENAME, for instance:
  #  Debian: VERSION_CODENAME=buster
  #  Fedora: VERSION_CODENAME=""
  #  Mint: UBUNTU_CODENAME=focal VERSION_CODENAME=una => focal una
  # $(sort) gets rid of duplicates (needed?)
  export LINUX_VERSION_CODENAME := $(sort $(shell sed -n -e 's/^VERSION_CODENAME=//p' -e 's/^UBUNTU_CODENAME=//p' /etc/os-release))
endif

ifndef LINUX_VERSION_ID
  export LINUX_VERSION_ID := $(shell sed -n -e 's/^VERSION_ID=//p' /etc/os-release)
endif

#(info LINUX_VARIANT=$(LINUX_VARIANT))
#(info LINUX_VERSION_ID=$(LINUX_VERSION_ID))
#(info LINUX_VERSION_CODENAME=$(LINUX_VERSION_CODENAME))

#
# Debian derived (Ubuntu, Mint?, ...)
#

ifneq ($(filter debian ubuntu,$(LINUX_VARIANT)),)
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /usr/share/dns/root.key
  CKSUM ?= shasum
  # https://wiki.debian.org/LTS
  ifeq ($(LINUX_VERSION_CODENAME),bullseye) # Debian 11; until June 30 2026
    USE_ML_KEM_768 ?= false
    USE_XFRM_HEADER_COPY ?= true
  endif
  ifeq ($(LINUX_VERSION_CODENAME),bookworm) # Debian 12; until June 30 2028
    USE_ML_KEM_768 ?= false
    USE_XFRM_HEADER_COPY ?= true
  endif
  ifeq ($(LINUX_VERSION_CODENAME),trixie) # Debian 13; until June 30 2030
    USE_XFRM_HEADER_COPY ?= true
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
# Alpine
#

ifneq ($(filter alpine,$(LINUX_VARIANT)),)
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /usr/share/dnssec-root/trusted-key.key
endif

#
# INITSYSTEM
#

ifndef INITSYSTEM
  ifneq ($(and $(wildcard /lib/systemd/systemd),$(wildcard /run/systemd)),)
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
# basic stuff (unless overridden by above)
#

USE_XFRM ?= true
USE_DNSSEC ?= true
ifneq ($(USE_IPTABLES), true)
  USE_NFTABLES ?= true
endif

# Opportunistic Encryption with NAT (Client Address Translation) support
# currently only supported on Linux
USE_CAT ?= true

# Linux NFLOG support
USE_NFLOG ?= true
