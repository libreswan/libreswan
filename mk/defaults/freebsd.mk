USERLAND_CFLAGS += -DHAS_SUN_LEN
USERLAND_CFLAGS += -DHAVE_IP_RECVDSTADDR=1
USERLAND_CFLAGS += -DHAVE_UDPFROMTO=1
USERLAND_CFLAGS += -DNEED_SIN_LEN
USERLAND_CFLAGS += -DTimeZoneOffset=timezone
USERLAND_CFLAGS += -Ds6_addr16=__u6_addr.__u6_addr16
USERLAND_CFLAGS += -Ds6_addr32=__u6_addr.__u6_addr32

PORTINCLUDE= -isystem /usr/local/include

# no KLIPS, we will be using FreeBSD copy of pfkey code.
USE_NETKEY=false
USE_WIN2K=false
USE_YACC=false

CRYPT_LDFLAGS =

USE_BSDKAME=true

# build modules, etc. for KLIPS.

USERLINK=-L/usr/local/lib -lcrypt

RANLIB=ranlib
