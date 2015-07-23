
# this is the debian installed mingw32 package.
CC=i586-mingw32msvc-gcc
AR=i586-mingw32msvc-ar
CYGWINDIR?=/0g/sandboxes/cygwin
SYSINCDIR=$(shell i586-mingw32msvc-gcc --print-file-name=include)
LIBGCC=$(shell i586-mingw32msvc-gcc --print-file-name=libgcc.a)
USERCOMPILE=-g -O3
PORTINCLUDE=-nostdinc -isystem ${SYSINCDIR}
PORTINCLUDE+=-isystem ${CYGWINDIR}include
PORTINCLUDE+=-I${LIBRESWANSRCDIR}/ports/win2k/include
USERCOMPILE+=-mcygwin -D__CYGWIN__ -D__CYGWIN32__
USERLINK=-mcygwin -nostdlib ${CYGWINDIR}/lib/crt0.o
USERLINK+=-L${CYGWINDIR}/lib -lcygwin ${LIBGCC}

USE_KLIPS=false
USE_NETKEY=false
USE_WIN2K=true
BUILD_KLIPS=false
