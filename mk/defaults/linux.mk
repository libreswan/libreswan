
KLIPSSRC=${LIBRESWANSRCDIR}/linux/net/ipsec

MODULE_DEF_INCLUDE=${LIBRESWANSRCDIR}/packaging/linus/config-all.h
MODULE_DEFCONFIG?=${KLIPSSRC}/defconfig
MOD24BUILDDIR?=${LIBRESWANSRCDIR}/modobj24
MODBUILDDIR?=${LIBRESWANSRCDIR}/modobj

MODULE_FLAGS:=KLIPSMODULE=true -f ${MODULE_DEFCONFIG}

PORTINCLUDE+=-I${LIBRESWANSRCDIR}/ports/linux/include
PORTDEFINE=-DSCANDIR_HAS_CONST

# include KLIPS support
USE_KLIPS?=true

# build modules, etc. for KLIPS.
BUILD_KLIPS?=true
BISONOSFLAGS=-g --verbose

# Detect linux variants and releases (for now just fedora and assume
# >= 22).
ifneq ($(wildcard /etc/fedora-release),)
LINUX_VARIANT?=fedora
endif

ifeq ($(LINUX_VARIANT),fedora)
USE_FIPSCHECK?=true
USE_LINUX_AUDIT?=true
endif
