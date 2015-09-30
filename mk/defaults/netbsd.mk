
PORTINCLUDE=
PORTINCLUDE+=-I${LIBRESWANSRCDIR}/ports/netbsd/include

PORTLASTINCLUDE=
PORTLASTINCLUDE+=-isystem /usr/local/include
PORTLASTINCLUDE+=-I/usr/pkg/include

PORTDEFINE+=-DHAS_SUN_LEN

PORTLDFLAGS=-L/usr/pkg/lib

# no KLIPS, we will be using FreeBSD copy of pfkey code.
USE_KLIPS=false
USE_KERNEL26=false
USE_PFKEYv2=false

USE_BSDKAME=true

NEEDS_GETOPT=true

# build modules, etc. for KLIPS.
BUILD_KLIPS=false

CFLAGS+=-DHAVE_SETPROCTITLE -DSCANDIR_HAS_CONST

USERLINK=-L/usr/local/lib -lcrypt

