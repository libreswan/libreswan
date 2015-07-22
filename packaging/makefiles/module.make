# I really am not happy about using symlinks to make this work.
#
# I think that there should be a better way to do this.
# see module26.sh in packaging/makefiles
#


ifndef LIBRESWANSRCDIR
$(error You Must set LIBRESWANSRCDIR)
endif

include ${LIBRESWANSRCDIR}/Makefile.inc

KLIPS_TOP := ${LIBRESWANSRCDIR}/linux

# include file with .h-style macros that would otherwise be created by
# config. Must occur before other includes.
ifneq ($(strip $(MODULE_EXTRA_INCLUDE)),)
EXTRA_CFLAGS += -include ${MODULE_EXTRA_INCLUDE}
endif

ifneq ($(strip $(MODULE_DEF_INCLUDE)),)
EXTRA_CFLAGS += -include ${MODULE_DEF_INCLUDE}
endif

# Enable DISABLE_UDP_CHECKSUM for KLIPS, see bug #601
EXTRA_CFLAGS += -DDISABLE_UDP_CHECKSUM

EXTRA_CFLAGS += -I${KLIPS_TOP}/include
EXTRA_CFLAGS += -I${KLIPSSRC}/.

# build version.c using version number from Makefile.ver
${BUILDDIR}/version.c:	${KLIPSSRC}/version.in.c ${LIBRESWANSRCDIR}/Makefile.ver
	sed '/"/s/@IPSECVERSION@/$(IPSECVERSION)/' ${KLIPSSRC}/version.in.c >$@

${BUILDDIR}/%.c : ${KLIPSSRC}/%.c
	ln -s -f $< $@

${BUILDDIR}/%.h : ${KLIPSSRC}/%.h
	ln -s -f $< $@

${BUILDDIR}/%.c : ${KLIPSSRC}/des/%.c
	ln -s -f $< $@

${BUILDDIR}/%.S : ${KLIPSSRC}/des/%.S
	ln -s -f $< $@

${BUILDDIR}/%.c : ${KLIPSSRC}/aes/%.c
	ln -s -f $< $@

${BUILDDIR}/%.c : ${KLIPSSRC}/alg/%.c
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
include ${LIBRESWANSRCDIR}/packaging/makefiles/module.defs
ifneq ($(strip $(MODULE_DEFCONFIG)),)
include ${MODULE_DEFCONFIG}
endif
include ${KLIPSSRC}/Makefile.fs2_6








