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
  #   Ubuntu: ID=ubuntu ID_LIKE=debian => ubuntu debian
  # $(sort) gets rid of duplicates (needed?)
  export LINUX_VARIANT := $(sort $(shell sed -n -e 's/"//g' -e 's/^ID_LIKE=//p' -e 's/^ID=//p' /etc/os-release))
endif

ifndef LINUX_VERSION_CODENAME
  # VERSION_CODENAME+UBUNTU_CODENAME, for instance:
  #  Debian: VERSION_CODENAME=buster
  #  Fedora: VERSION_CODENAME=""
  #  Mint: UBUNTU_CODENAME=focal VERSION_CODENAME=una => focal una # no debian?
  #  Ubuntu: UBUNTU_CODENAME=jammy VERSION_CODENAME=jammy DISTRIB_CODENAME=jammy
  # $(sort) gets rid of duplicates (needed? yes)
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

  # DEBIAN
  # https://wiki.debian.org/LTS

  ifeq ($(LINUX_VERSION_CODENAME),bullseye) # Debian 11; Jun 2026; June 2031
    USE_XFRM_HEADER_COPY ?= true
    # NSS=3.61; EDDSA>=3.99 ML_KEM>3.118
    USE_ML_KEM_768 ?= false
    USE_ML_KEM_1024 ?= false
    USE_EDDSA ?= false
  endif

  ifeq ($(LINUX_VERSION_CODENAME),bookworm) # Debian 12; Jun 2028; June 2033
    USE_XFRM_HEADER_COPY ?= true
    # NSS=3.87; EDDSA>=3.99 ML_KEM>3.118
    USE_ML_KEM_768 ?= false
    USE_ML_KEM_1024 ?= false
    USE_EDDSA ?= false
  endif

  ifeq ($(LINUX_VERSION_CODENAME),trixie) # Debian 13; Jun 2030; June 2035
    USE_XFRM_HEADER_COPY ?= true
    # NSS=3.110; EDDSA>=3.99 ML_KEM>3.118
    USE_ML_KEM_768 ?= false
    USE_ML_KEM_1024 ?= false
  endif

  ifeq ($(LINUX_VERSION_CODENAME),forkey) # Debian 14; TBD
    # NSS=3.124; EDDSA>=3.99 ML_KEM>3.118
  endif

  # UBUNTU
  # https://ubuntu.com/about/release-cycle

  ifeq ($(LINUX_VERSION_CODENAME),focal) # Ubuntu 20.04.6 LTS; May 2025; Pro Apr 2030
    USE_XFRM_HEADER_COPY ?= true
    USE_ML_KEM_768 ?= false
    USE_ML_KEM_1024 ?= false
    USE_EDDSA ?= false
  endif

  ifeq ($(LINUX_VERSION_CODENAME),jammy) # Ubuntu 22.04.5 LTS; Jun 2027; Pro Apr 2032
    USE_XFRM_HEADER_COPY ?= true
    # NSS 3.98; EDDSA>=3.99
    USE_ML_KEM_768 ?= false
    USE_EDDSA ?= false
  endif

  ifeq ($(LINUX_VERSION_CODENAME),noble) # Ubuntu 24.04.3 LTS; May 2029; Pro Apr 2034
    USE_XFRM_HEADER_COPY ?= true
    USE_ML_KEM_768 ?= false
    USE_ML_KEM_1024 ?= false
    USE_EDDSA ?= false
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
  # vfychain on Fedora isn't in the default path.
  VFYCHAIN ?= /usr/lib64/nss/unsupported-tools/vfychain
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
  INITSYSTEM=openrc
endif


#
# OpenWRT
#

ifneq ($(filter openwrt,$(LINUX_VARIANT)),)
  DEFAULT_DNSSEC_ROOTKEY_FILE ?= /var/lib/unbound/root.key
  INITSYSTEM=sysvinit
endif


#
# basic stuff (unless overridden by above)
#

# Alpine and OpenWRT continue to resist the tide.
INITSYSTEM ?= systemd

USE_XFRM ?= true
ifneq ($(USE_IPTABLES), true)
  USE_NFTABLES ?= true
endif

# Opportunistic Encryption with NAT (Client Address Translation)
# support currently only supported on Linux.
USE_CAT ?= true

# Linux NFLOG support
USE_NFLOG ?= true
