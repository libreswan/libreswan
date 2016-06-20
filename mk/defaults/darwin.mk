CC=gcc
PORTINCLUDE+=-I${LIBRESWANSRCDIR}/ports/darwin/include -I/opt/local/include
USERLINK=-L/usr/local/lib -L/opt/local/lib

USE_MAST=false
USE_KLIPS=false
USE_NETKEY=false
USE_WIN2K=false
BUILD_KLIPS=false
# no longer needed now the bison/yacc options got updated
USE_YACC=false

USE_BSDKAME=true

# This should really be fixed, only a few debug/logging functions are used
USE_PFKEYv2=true

# build modules, etc. for KLIPS.
BUILD_KLIPS=false

#not sure where this is supposed to come from, but the linux port has AR here
RANLIB=ranlib

# Darwin apparently doesn't have setschedprio
USE_PTHREAD_SETSCHEDPRIO=false
