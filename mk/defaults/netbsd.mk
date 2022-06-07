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
USE_BSDKAME = true
USE_PFKEYV2 = true
USE_LIBCAP_NG = false

INITSYSTEM=rc.d

USE_DNSSEC = true
DEFAULT_DNSSEC_ROOTKEY_FILE = /usr/pkg/etc/unbound/root.key

# not /run/pluto
FINALRUNDIR=/var/run/pluto

# PREFIX = /usr/local from mk/config.mk
FINALSYSCONFDIR=$(PREFIX)/etc
FINALNSSDIR=$(PREFIX)/etc/ipsec.d
FINALEXAMPECONFDIR=$(PREFIX)/share/examples/libreswan
