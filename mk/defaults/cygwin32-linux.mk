
# this is the debian installed mingw32 package.
CC=/xelerance/cross/win2k/bin/i686-pc-cygwin-gcc
AR=/xelerance/cross/win2k/bin/i686-pc-cygwin-ar
USERCOMPILE=-g -O3
USERCOMPILE+=-mcygwin -D__CYGWIN__ -D__CYGWIN32__
USERLINK=-L/0g/sandboxes/cygwin/lib -mcygwin
OSDEP=cygwin

PORTINCLUDE+=-I${LIBRESWANSRCDIR}/ports/win2k/include

USE_KLIPS=false
USE_NETKEY=false
USE_WIN2K=true
BUILD_KLIPS=false
