#!/bin/sh
#
# cross compile example
#


#export PREFIX=/volquad/arm-4.0.2
export PREFIX=/usr/local/arm_tools
export DESTDIR=/tmp/libreswan.arm

export ARCH=arm
export CC=$PREFIX/bin/arm-elf-gcc
export GCC=$PREFIX/bin/arm-elf-gcc
export LD=$PREFIX/bin/arm-elf-ld
export RANLIB=$PREFIX/bin/arm-elf-ranlib
export AR=$PREFIX/bin/arm-elf-ar
export AS=$PREFIX/bin/arm-elf-as
export STRIP=$PREFIX/bin/arm-elf-strip
export LD_LIBRARY_PATH=$PREFIX/lib/gcc-lib/arm-elf/3.0/
export PATH=$PATH:$PREFIX/bin
export USERCOMPILE="-Wl,-elf2flt -DCOMPILER_HAS_NO_PRINTF_LIKE -O3 -g ${PORTDEFINE} -I$PREFIX/arm-elf/inc -L$PREFIX/lib/gcc-lib -DGCC_LINT -Dlinux -D__linux__"
export WERROR=' '

#now you can run:
# make programs
#and binaries will appear in OBJ.linux.$ARCH/
#and run:
# make install
#and the install will go into $DESTDIR/

# note: the arm_tools I had failed to compile PRINTF_LIKE(x), so the code
# for that was  ifdef'ed with #ifndef COMPILER_HAS_NO_PRINTF_LIKE statements.
# Add -DCOMPILER_HAS_NO_PRINTF_LIKE to enable the workaround.

# EXECUTABLE FILE FORMAT
#
# Some uClibc/busybox combinations use different executable files formats from
# ELF. This is configured during Linux kernel build. One common format is
# the BLFT file format. Do not manually convert ELF binaries to BLTF using
# elf2flt as that will create invalid binaries. Instead add -Wl,-elf2flt to
# your flags (CFLAGS / LDFLAGS / USERCOMPILE)
