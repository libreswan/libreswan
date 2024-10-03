BSD_VARIANT=netbsd
# sketch out pkgsrc
PKG_BASE ?= /usr/pkg
PKG_DBDIR ?= /var/db/pkg
PKG_PATH ?= /usr/pkgsrc/packages/All

USERLAND_CFLAGS += -DUSE_SOCKADDR_LEN

USERLAND_INCLUDES += -I$(PKG_BASE)/include

USERLAND_LDFLAGS += -L$(PKG_BASE)/lib -Wl,-rpath,$(PKG_BASE)/lib

# NSS includes more than needed in ldflags
NSS_LDFLAGS = -L$(PKG_BASE)/lib/nss -Wl,-rpath,$(PKG_BASE)/lib/nss -lnss3 -lfreebl3 -lssl3
NSPR_LDFLAGS = -L$(PKG_BASE)/lib/nspr -Wl,-rpath,$(PKG_BASE)/lib/nspr -lnspr4

CRYPT_LDFLAGS =

LIBEVENT_LDFLAGS = -levent -levent_pthreads
USE_PFKEYV2 = true
USE_LIBCAP_NG = false

INITSYSTEM=rc.d

USE_DNSSEC = true
DEFAULT_DNSSEC_ROOTKEY_FILE = /usr/pkg/etc/unbound/root.key

# not /run/pluto
RUNDIR=/var/run/pluto

# PREFIX = /usr/local from mk/config.mk
SYSCONFDIR=$(PREFIX)/etc
NSSDIR=$(PREFIX)/etc/ipsec.d
EXAMPLE_IPSEC_SYSCONFDIR=$(PREFIX)/share/examples/libreswan
# Not $(PREFIX)/share/man
MANDIR=$(PREFIX)/man

# LTO seems either broken or confused
USE_LTO ?= false

# CHACHA is embedded in the ESP proposal (it shouldn't) this removes
# it, but also removes it from IKE, oops.
USE_CHACHA = false
