USERLAND_CFLAGS += -I/usr/pkg/include
USERLAND_CFLAGS += -DHAS_SUN_LEN
USERLAND_CFLAGS += -DNEED_SIN_LEN
USERLAND_CFLAGS += -DHAVE_NETINET6_IN_H
USERLAND_CFLAGS += -DHAVE_UDPFROMTO
USERLAND_CFLAGS += -DHAVE_IP_RECVDSTADDR
USERLAND_CFLAGS += -Ds6_addr16=__u6_addr.__u6_addr16
USERLAND_CFLAGS += -Ds6_addr32=__u6_addr.__u6_addr32

USE_BSDKAME=true
USE_LIBCAP_NG=false

LDFLAGS +=  -lipsec -L/usr/pkg/lib -Wl,-rpath,/usr/pkg/lib

NSSFLAGS = -I/usr/pkg/include/nspr -I/usr/pkg/include/nss/nss
NSS_LDFLAGS = -L/usr/pkg/lib/nss -Wl,-rpath,/usr/pkg/lib/nss -lnss3 -lfreebl3 -lssl3
NSPR_LDFLAGS = -L/usr/pkg/lib/nspr -Wl,-rpath,/usr/pkg/lib/nspr -lnspr4

CRYPT_LDFLAGS =

INITSYSTEM=

FINAL_PAM_D_DIR=/usr/local/etc/pam.d
FINALSYSCONFDIR=/usr/local/etc
FINALRUNDIR=/usr/local/run/pluto
FINALNSSDIR=/usr/local/etc/ipsec.d
