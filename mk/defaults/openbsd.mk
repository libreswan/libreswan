BSD_VARIANT = openbsd
# sketch out pkgsrc
PKG_BASE ?= /usr/local

# See: https://github.com/llvm/llvm-project/issues/55963
# See: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=264288
# See: https://github.com/libreswan/libreswan/issues/735
# OpenBSD seems to call GCC egcc
#CC=egcc
CC=clang-18

WARNING_CFLAGS += -Wself-assign
USERLAND_CFLAGS += -DUSE_SOCKADDR_LEN

# hack around broken LDNS header referring to undefined USE_ED448
USERLAND_CFLAGS += -DUSE_ED448=LDNS_BUILD_CONFIG_USE_ED448

USERLAND_INCLUDES += -I$(PKG_BASE)/include

USERLAND_LDFLAGS += -L$(PKG_BASE)/lib -Wl,-rpath,$(PKG_BASE)/lib

# NSS includes more than needed in ldflags
NSS_LDFLAGS = -L$(PKG_BASE)/lib/nss -Wl,-rpath,$(PKG_BASE)/lib/nss -lnss3 -lfreebl3 -lssl3
NSPR_LDFLAGS = -L$(PKG_BASE)/lib/nspr -Wl,-rpath,$(PKG_BASE)/lib/nspr -lnspr4

USE_PFKEYV2 = true
CRYPT_LDFLAGS =
RT_LDFLAGS =

USE_LIBCAP_NG = false
USE_PTHREAD_SETSCHEDPRIO = false
USE_AUTHPAM = false

USE_DNSSEC = true
DEFAULT_DNSSEC_ROOTKEY_FILE = /var/unbound/db/root.key

INITSYSTEM=rc.d

# not /run/pluto
RUNDIR=/var/run/pluto
# Not $(PREFIX)/share/man
MANDIR=$(PREFIX)/man

# PREFIX = /usr/local from mk/config.mk
SYSCONFDIR=$(PREFIX)/etc
NSSDIR=$(PREFIX)/etc/ipsec.d
EXAMPLE_IPSEC_SYSCONFDIR=$(PREFIX)/share/examples/libreswan

# LTO seems either broken or confused
USE_LTO ?= false

# not LOG_WARNING!
DEFAULT_LOGLEVEL=LOG_NOTICE
