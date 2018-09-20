USERLAND_CFLAGS += -DTimeZoneOffset=timezone
USERLAND_CFLAGS += -Ds6_addr16=__u6_addr.__u6_addr16
USERLAND_CFLAGS += -Ds6_addr32=__u6_addr.__u6_addr32
USERLAND_CFLAGS += -DNEED_SIN_LEN
USERLAND_CFLAGS += -D__APPLE_USE_RFC_3542

CC=gcc
PORTINCLUDE= -I/opt/local/include
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

CRYPT_LDFLAGS =

#not sure where this is supposed to come from, but the linux port has AR here
RANLIB=ranlib

# Darwin apparently doesn't have setschedprio
USE_PTHREAD_SETSCHEDPRIO=false

USE_LIBCAP_NG=false
USE_NM=false

# On MAC OSX use different backup file suffix.
#
# This assumes that when cross compiling for darwin, a cross installer
# is being used.
INSTBINFLAGS=-D -b -B .old
