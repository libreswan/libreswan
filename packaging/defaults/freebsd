
PORTINCLUDE+=-I${LIBRESWANSRCDIR}/ports/freebsd/include -isystem /usr/local/include
PORTDEFINE+=-DHAS_SUN_LEN -DNEED_SIN_LEN

# no KLIPS, we will be using FreeBSD copy of pfkey code.
USE_MAST=false
USE_KLIPS=false
USE_NETKEY=false
USE_WIN2K=false
USE_YACC=false


USE_BSDKAME=true

# build modules, etc. for KLIPS.
BUILD_KLIPS=false

CFLAGS+=-DHAVE_SETPROCTITLE

USERLINK=-L/usr/local/lib -lcrypt

RANLIB=ranlib
