# I really am not happy about using symlinks to make this work.
#
# I think that there should be a better way to do this.
# see module26.sh in packaging/makefiles
#


ifndef OPENSWANSRCDIR
$(error You Must set OPENSWANSRCDIR)
endif

include ${OPENSWANSRCDIR}/Makefile.inc

KLIPS_TOP := ${OPENSWANSRCDIR}/linux

# include file with .h-style macros that would otherwise be created by
# config. Must occur before other includes.
ifneq ($(strip $(MODULE_DEF_INCLUDE)),)
EXTRA_CFLAGS += -include ${MODULE_DEF_INCLUDE}
endif

# Enable DISABLE_UDP_CHECKSUM for KLIPS, see bug #601
EXTRA_CFLAGS += -DDISABLE_UDP_CHECKSUM

EXTRA_CFLAGS += -I${KLIPS_TOP}/include

# build version.c using version number from Makefile.ver
${BUILDDIR}/version.c:	${KLIPSSRC}/version.in.c ${OPENSWANSRCDIR}/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' ${KLIPSSRC}/version.in.c >$@

${BUILDDIR}/%.c : ${KLIPSSRC}/%.c
	ln -s -f $< $@

${BUILDDIR}/%.h : ${KLIPSSRC}/%.h
	ln -s -f $< $@

.PRECIOUS: ${BUILDDIR}/%.c ${BUILDDIR}/%.h

# I'm not fixing this in a better way, because we should use the
# in-kernel zlib!
${BUILDDIR}/deflate.c: ${BUILDDIR}/deflate.h
${BUILDDIR}/infblock.c: ${BUILDDIR}/infblock.h ${BUILDDIR}/inftrees.h
${BUILDDIR}/infblock.c: ${BUILDDIR}/infcodes.h  ${BUILDDIR}/infutil.h
${BUILDDIR}/infcodes.c: ${BUILDDIR}/inffast.h
${BUILDDIR}/inftrees.c: ${BUILDDIR}/inffixed.h
${BUILDDIR}/trees.c: ${BUILDDIR}/trees.h

MODULE26=true
include ${OPENSWANSRCDIR}/packaging/makefiles/module.defs 
ifneq ($(strip $(MODULE_DEFCONFIG)),)
include ${MODULE_DEFCONFIG}
endif
include ${KLIPSSRC}/Makefile.fs2_6







