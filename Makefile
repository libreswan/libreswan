# Openswan master makefile
# Copyright (C) 1998-2002  Henry Spencer.
# Copyright (C) 2003-2004  Xelerance Corporation
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.273.2.4 2005/09/13 22:09:28 mcr Exp $


OPENSWANSRCDIR?=$(shell pwd)
export OPENSWANSRCDIR

include ${OPENSWANSRCDIR}/Makefile.inc

srcdir?=$(shell pwd)

# dummy default rule
def:
	@echo "Please read the README for detailed build instructions including how"
	@echo "to enable NAT-T support for your kernel, if desired"
	@echo
	@echo "Commonly used build commands:"
	@echo
	@echo "Kernel 2.4: make KERNELSRC=/usr/src/linux-2.4 module minstall programs install"
	@echo "Kernel 2.6: make programs install"
	@echo
	@echo

include ${OPENSWANSRCDIR}/Makefile.top

# kernel details
# what variant of our patches should we use, and where is it
KERNELREL=$(shell ${KVSHORTUTIL} ${KERNELSRC}/Makefile)

# directories visited by all recursion

# declaration for make's benefit
.PHONY:	def insert kpatch klink patches _patches _patches2.2 _patches2.4 \
	klipsdefaults programs install clean distclean \
	ogo oldgo menugo xgo \
	omod menumod xmod \
	pcf ocf mcf xcf rcf nopromptgo \
	precheck verset confcheck kernel \
	module module24 module26 kinstall minstall minstall24 minstall26 \
	backup unpatch uinstall install_file_list \
	snapready relready ready buildready devready uml check taroldinstall \
	umluserland


kpatch: unapplypatch applypatch klipsdefaults
npatch: unapplynpatch applynpatch

unapplypatch:
	-@if [ -f ${KERNELSRC}/openswan.patch ]; then \
		echo Undoing previous patches; \
		cat ${KERNELSRC}/openswan.patch | (cd ${KERNELSRC} && patch -p1 -R --force -E -z .preipsec --reverse --ignore-whitespace ); \
	fi

applypatch:
	@echo Now performing forward patches; 
	make kernelpatch${KERNELREL} | tee ${KERNELSRC}/openswan.patch | (cd ${KERNELSRC} && patch -p1 -b -z .preipsec --forward --ignore-whitespace )

unapplynpatch:
	-@if [ -f ${KERNELSRC}/natt.patch ]; then \
		echo Undoing previous NAT patches; \
		cat ${KERNELSRC}/natt.patch | (cd ${KERNELSRC} && patch -p1 -R --force -E -z .preipsec --reverse --ignore-whitespace ); \
	fi

applynpatch:
	@echo Now performing forward NAT patches; 
	make nattpatch${KERNELREL} | tee ${KERNELSRC}/natt.patch | (cd ${KERNELSRC} && patch -p1 -b -z .preipsec --forward --ignore-whitespace )

# patch kernel
PATCHER=packaging/utils/patcher

patches:
	@echo \"make patches\" is obsolete. See \"make kpatch\".
	exit 1

_patches:
	echo "===============" >>out.kpatch
	echo "`date` `cd $(KERNELSRC) ; pwd`" >>out.kpatch
	$(MAKE) __patches$(KERNELREL) >>out.kpatch

# Linux-2.0.x version
__patches __patches2.0:
	@$(PATCHER) -v $(KERNELSRC) Documentation/Configure.help \
	  'CONFIG_KLIPS' $(PATCHES)/Documentation/Configure.help.fs2_0.patch
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
	  'CONFIG_KLIPS' $(PATCHES)/net/Config.in.fs2_0.patch
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
	  'CONFIG_KLIPS' $(PATCHES)/net/Makefile.fs2_0.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
	  'CONFIG_KLIPS' $(PATCHES)/net/ipv4/af_inet.c.fs2_0.patch
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.2.x version
PATCHES24=klips/patches2.3
__patches2.2:
	@$(PATCHER) -v -c $(KERNELSRC) Documentation/Configure.help \
	  'CONFIG_KLIPS' $(PATCHES)/Documentation/Configure.help.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_KLIPS' $(PATCHES)/net/Config.in.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_KLIPS' $(PATCHES)/net/Makefile.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_KLIPS' $(PATCHES)/net/ipv4/af_inet.c.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/udp.c \
		'CONFIG_KLIPS' $(PATCHES)/net/ipv4/udp.c.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) include/net/sock.h \
		'CONFIG_KLIPS' $(PATCHES)/include/net/sock.h.fs2_2.patch
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.4.0 version
PATCHES22=klips/patches2.2
__patches2.3 __patches2.4:
	@$(PATCHER) -v -c $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_KLIPS' $(PATCHES)/Documentation/Configure.help.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_KLIPS' $(PATCHES)/net/Config.in.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_KLIPS' $(PATCHES)/net/Makefile.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_KLIPS' $(PATCHES)/net/ipv4/af_inet.c.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/udp.c \
		'CONFIG_KLIPS' $(PATCHES)/net/ipv4/udp.c.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) include/net/sock.h \
		'CONFIG_KLIPS' $(PATCHES)/include/net/sock.h.fs2_4.patch
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

klipsdefaults:
	@KERNELDEFCONFIG=$(KERNELSRC)/arch/$(ARCH)/defconfig ; \
	KERNELCONFIG=$(KCFILE) ; \
	if ! egrep -q 'CONFIG_KLIPS' $$KERNELDEFCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELDEFCONFIG $$KERNELDEFCONFIG.orig ; \
		chmod u+w $$KERNELDEFCONFIG ; \
		cat $$KERNELDEFCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELDEFCONFIG.tmp ; \
		rm -f $$KERNELDEFCONFIG ; \
		cp -a $$KERNELDEFCONFIG.tmp $$KERNELDEFCONFIG ; \
		rm -f $$KERNELDEFCONFIG.tmp ; \
	fi ; \
	if ! egrep -q 'CONFIG_KLIPS' $$KERNELCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELCONFIG $$KERNELCONFIG.orig ; \
		chmod u+w $$KERNELCONFIG ; \
		cat $$KERNELCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELCONFIG.tmp ; \
		rm -f $$KERNELCONFIG ; \
		cp -a $$KERNELCONFIG.tmp $$KERNELCONFIG ; \
		rm -f $$KERNELCONFIG.tmp ; \
	fi



# programs

ifeq ($(strip $(OBJDIR)),.)
programs install clean:: 
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${OPENSWANSRCDIR}/$$d/ OPENSWANSRCDIR=${OPENSWANSRCDIR} $@ ) || exit 1; \
	done; 

else
ABSOBJDIR:=$(shell mkdir -p ${OBJDIR}; cd ${OBJDIR} && pwd)

programs install clean:: ${OBJDIR}/Makefile
	@echo OBJDIR: ${OBJDIR}
	(cd ${ABSOBJDIR} && OBJDIRTOP=${ABSOBJDIR} OBJDIR=${ABSOBJDIR} make $@ )

${OBJDIR}/Makefile: ${srcdir}/Makefile packaging/utils/makeshadowdir
	@echo Setting up for OBJDIR=${OBJDIR}
	@packaging/utils/makeshadowdir `(cd ${srcdir}; pwd)` ${OBJDIR} "${SUBDIRS}"

endif

checkprograms:: 
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${OPENSWANSRCDIR}/$$d/ OPENSWANSRCDIR=${OPENSWANSRCDIR} $@ ) || exit 1; \
	done; 

checkv199install:
	@if [ "${LIBDIR}" != "${LIBEXECDIR}" ] && [ -f ${LIBDIR}/pluto ]; \
	then \
		echo WARNING: Old version of FreeS/WAN Openswan 1.x installed. ;\
		echo WARNING: moving ${LIBDIR} to ${LIBDIR}.v1 ;\
		mv ${LIBDIR} ${LIBDIR}.v1 ;\
	fi

install:: checkv199install

clean::
	rm -rf $(RPMTMPDIR) $(RPMDEST)
	rm -f out.*build out.*install	# but leave out.kpatch
	rm -f rpm.spec

# proxies for major kernel make operations

# do-everything entries
KINSERT_PRE=precheck verset insert
PRE=precheck verset kpatch
POST=confcheck programs kernel install 
MPOST=confcheck programs module install 
#ogo:		$(PRE) pcf $(POST)
#oldgo:		$(PRE) ocf $(POST)
#nopromptgo:	$(PRE) rcf $(POST)
#menugo:		$(PRE) mcf $(POST)
#xgo:		$(PRE) xcf $(POST)

ogo: obsolete_target
oldgo: obsolete_target
nopromptgo: obsolete_target
menugo: obsolete_target
xgo: obsolete_target
obsolete_target:
	@echo "The targets ogo, oldgo, menugo, nopromptgo and xgo are obsolete. Please read INSTALL"

# preliminaries
precheck:
	@if test ! -d $(KERNELSRC) -a ! -L $(KERNELSRC) ; \
	then \
		echo '*** cannot find directory "$(KERNELSRC)"!!' ; \
		echo '*** may be necessary to add symlink to kernel source' ; \
		exit 1 ; \
	fi
	@if ! cd $(KERNELSRC) ; \
	then \
		echo '*** cannot "cd $(KERNELSRC)"!!' ; \
		echo '*** may be necessary to add symlink to kernel source' ; \
		exit 1 ; \
	fi
	@if test ! -f $(KCFILE) ; \
	then \
		echo '*** cannot find "$(KCFILE)"!!' ; \
		echo '*** perhaps kernel has never been configured?' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi
	@if test ! -f $(VERFILE) ; \
	then \
		echo '*** cannot find "$(VERFILE)"!!' ; \
		echo '*** perhaps kernel has never been compiled?' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi

# set version code if this is a fresh CVS checkout
ifeq ($(wildcard cvs.datemark),cvs.datemark)
verset Makefile.ver: cvs.datemark
	echo IPSECVERSION=`date -r cvs.datemark +cvs%Y%b%d_%H:%M:%S` >Makefile.ver 
	rm -f cvs.datemark; 
else
verset Makefile.ver: 
	@grep IPSECVERSION Makefile.ver
endif

Makefile: Makefile.ver

# configuring (exit statuses disregarded, something fishy here sometimes)
xcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) xconfig
mcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) menuconfig
pcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) config

ocf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) oldconfig 

rcf:
	cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) ${NONINTCONFIG} </dev/null
	cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) dep >/dev/null

kclean:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) clean

confcheck:
	@if test ! -f $(KCFILE) ; \
	then echo '*** no kernel configuration file written!!' ; exit 1 ; \
	fi
	@if ! egrep -q '^CONFIG_KLIPS=[my]' $(KCFILE) ; \
	then echo '*** IPsec not in kernel config ($(KCFILE))!!' ; exit 1 ; \
	fi
	@if ! egrep -q 'CONFIG_KLIPS[ 	]+1' $(ACFILE) && \
		! egrep -q 'CONFIG_KLIPS_MODULE[ 	]+1' $(ACFILE) ; \
	then echo '*** IPsec in kernel config ($(KCFILE)),' ; \
		echo '***	but not in config header file ($(ACFILE))!!' ; \
		exit 1 ; \
	fi
	@if egrep -q '^CONFIG_KLIPS=m' $(KCFILE) && \
		! egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then echo '*** IPsec configured as module in kernel with no module support!!' ; exit 1 ; \
	fi
	@if ! egrep -q 'CONFIG_KLIPS_AH[ 	]+1' $(ACFILE) && \
		! egrep -q 'CONFIG_KLIPS_ESP[ 	]+1' $(ACFILE) ; \
	then echo '*** IPsec configuration must include AH or ESP!!' ; exit 1 ; \
	fi

# kernel building, with error checks
kernel:
	rm -f out.kbuild out.kinstall
	# undocumented kernel folklore: clean BEFORE dep. 
	# we run make dep seperately, because there is no point in running ERRCHECK
	# on the make dep output.
	# see LKML thread "clean before or after dep?"
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) $(KERNCLEAN) $(KERNDEP) )
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) $(KERNEL) ) 2>&1 | tee out.kbuild
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) modules 2>&1 ) | tee -a out.kbuild ; \
	fi
	${ERRCHECK} out.kbuild

# this target takes a kernel source tree and it builds a link tree,
# and then does make oldconfig for each .config file that was found in configs.
# The location for the disk space required for the link tree is found via
# $RH_KERNELSRC_POOL
preprhkern4module:
	if [ -z "${RH_KERNELSRC_POOL}" ]; then echo Please set RH_KERNELSRC_POOL.; exit 1; fi
	mkdir -p ${RH_KERNELSRC_POOL}
	KV=`${KVUTIL} $(RH_KERNELSRC)/Makefile` ; \
	cd ${RH_KERNELSRC_POOL} && \
	mkdir -p $$KV && cd $$KV && \
	for config in ${RH_KERNELSRC}/configs/*; do \
		basecfg=`basename $$config` ;\
		mkdir -p ${RH_KERNELSRC_POOL}/$$KV/$$basecfg && \
		cd ${RH_KERNELSRC_POOL}/$$KV/$$basecfg && \
		lndir ${RH_KERNELSRC} . && \
		rm -rf include/asm && \
		(cd include/linux && sed -e '/#include "\/boot\/kernel.h"/d' <rhconfig.h >rhconfig.h-new && mv rhconfig.h-new rhconfig.h ) && \
		rm -f include/linux/modules/*.stamp && \
		make dep && \
		make oldconfig; \
	done;

# module-only building, with error checks
ifneq ($(strip $(MODBUILDDIR)),)
${MODBUILDDIR}/Makefile : ${OPENSWANSRCDIR}/packaging/makefiles/module.make
	mkdir -p ${MODBUILDDIR}
	cp ${OPENSWANSRCDIR}/packaging/makefiles/module.make ${MODBUILDDIR}/Makefile
	echo "# "                        >> ${MODBUILDDIR}/Makefile
	echo "# Local Variables: "       >> ${MODBUILDDIR}/Makefile
	echo "# compile-command: \"${MAKE} OPENSWANSRCDIR=${OPENSWANSRCDIR} ARCH=${ARCH} TOPDIR=${KERNELSRC} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} MODULE_DEFCONFIG=${MODULE_DEFCONFIG} -f Makefile ipsec.o\""         >> ${MODBUILDDIR}/Makefile
	echo "# End: "       >> ${MODBUILDDIR}/Makefile

module:
	@if [ -f ${KERNELSRC}/README.openswan-2 ] ; then \
                echo "WARNING: Kernel source ${KERNELSRC} has already been patched with openswan-2, out of tree build might fail!"; \
        fi;
	@if [ -f ${KERNELSRC}/README.freeswan ] ; then \
                echo "ERROR: Kernel source ${KERNELSRC} has already been patched with freeswan, out of tree build will fail!"; \
        fi;
	@if [ -f ${KERNELSRC}/Rules.make ] ; then \
                echo "Building module for a 2.4 kernel"; ${MAKE} module24 ; \
        else echo "Building module for a 2.6 kernel"; ${MAKE} module26; \
        fi;

module24:
	@if [ ! -f ${KERNELSRC}/Rules.make ] ; then \
                echo "Warning: Building for a 2.4 kernel in what looks like a 2.6 tree"; \
        fi ; \
        ${MAKE} ${MODBUILDDIR}/Makefile
	${MAKE} -C ${MODBUILDDIR}  OPENSWANSRCDIR=${OPENSWANSRCDIR} ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} TOPDIR=${KERNELSRC} -f Makefile ipsec.o
	@echo 
	@echo '========================================================='
	@echo 
	@echo 'KLIPS module built successfully. '
	@echo ipsec.o is in ${MODBUILDDIR}
	@echo 
	@(cd ${MODBUILDDIR}; ls -l ipsec.o)
	@(cd ${MODBUILDDIR}; size ipsec.o)
	@echo 
	@echo 'use make minstall as root to install it'
	@echo 
	@echo '========================================================='
	@echo 

modclean: 
	rm -rf ${MODBUILDDIR}

#autoodetect 2.4 and 2.6
module_install: minstall
minstall:
	@if [ -f ${KERNELSRC}/Rules.make ] ; then \
                ${MAKE} minstall24 ; else ${MAKE} minstall26; \
        fi;

# module-only install, with error checks
minstall24:
	( OSMODLIB=`make -C $(KERNELSRC) -p dummy | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	if [ -z "$$OSMODLIB" ] ; then \
		OSMODLIB=`make -C $(KERNELSRC) -n -p modules_install | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	fi ; \
	if [ -z "$$OSMODLIB" ] ; then \
		echo "No known place to install module. Aborting." ; \
		exit 93 ; \
	fi ; \
	set -x ; \
	mkdir -p $$OSMODLIB/kernel/$(OSMOD_DESTDIR) ; \
	cp $(MODBUILDDIR)/ipsec.o $$OSMODLIB/kernel/$(OSMOD_DESTDIR) ; \
	if [ -f /sbin/depmod ] ; then depmod -a ; fi; \
	if [ -n "$(OSMOD_DESTDIR)" ] ; then \
        mkdir -p $$OSMODLIB/kernel/$(OSMOD_DESTDIR) ; \
                if [ -f $$OSMODLIB/kernel/ipsec.o -a -f $$OSMODLIB/kernel/$(OSMOD_DESTDIR)/ipsec.o ] ; then \
                        echo "WARNING: two ipsec.o modules found in $$OSMODLIB/kernel:" ; \
                        ls -l $$OSMODLIB/kernel/ipsec.o $$OSMODLIB/kernel/$(OSMOD_DESTDIR)/ipsec.o ; \
                        exit 1; \
                fi ; \
        fi ; \
        set -x ) ;


else
module: 
	echo 'Building in place is no longer supported. Please set MODBUILDDIR='
	exit 1

endif

# module-only building, with error checks
ifneq ($(strip $(MOD26BUILDDIR)),)
${MOD26BUILDDIR}/Makefile : ${OPENSWANSRCDIR}/packaging/makefiles/module26.make
	mkdir -p ${MOD26BUILDDIR}
	echo ln -s -f ${OPENSWANSRCDIR}/linux/net/ipsec/des/*.S ${MOD26BUILDDIR}
	(rm -f ${MOD26BUILDDIR}/des; mkdir -p ${MOD26BUILDDIR}/des && cd ${MOD26BUILDDIR}/des && ln -s -f ${OPENSWANSRCDIR}/linux/net/ipsec/des/* . && ln -s -f Makefile.fs2_6 Makefile)
	(rm -f ${MOD26BUILDDIR}/aes; mkdir -p ${MOD26BUILDDIR}/aes && cd ${MOD26BUILDDIR}/aes && ln -s -f ${OPENSWANSRCDIR}/linux/net/ipsec/aes/* . && ln -s -f Makefile.fs2_6 Makefile)
	mkdir -p ${MOD26BUILDDIR}/aes
	cp ${OPENSWANSRCDIR}/packaging/makefiles/module26.make ${MOD26BUILDDIR}/Makefile
	echo "# "                        >> ${MOD26BUILDDIR}/Makefile
	echo "# Local Variables: "       >> ${MOD26BUILDDIR}/Makefile
	echo "# compile-command: \"${MAKE} -C ${OPENSWANSRCDIR} ARCH=${ARCH} KERNELSRC=${KERNELSRC} MOD26BUILDDIR=${MOD26BUILDDIR} module26\""         >> ${MOD26BUILDDIR}/Makefile
	echo "# End: "       >> ${MOD26BUILDDIR}/Makefile
	ln -s -f ${OPENSWANSRCDIR}/linux/net/ipsec/match*.S ${MOD26BUILDDIR}

module26:
	@if [ -f ${KERNELSRC}/Rules.make ] ; then \                 echo "Warning: Building for a 2.6 kernel in what looks like a 2.4 tree"; \
        fi ; \
        ${MAKE}  ${MOD26BUILDDIR}/Makefile
	${MAKE} -C ${KERNELSRC} ${KERNELBUILDMFLAGS} BUILDDIR=${MOD26BUILDDIR} SUBDIRS=${MOD26BUILDDIR} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} MODULE_DEFCONFIG=${MODULE_DEFCONFIG}  MODULE_EXTRA_INCLUDE=${MODULE_EXTRA_INCLUDE} ARCH=${ARCH} modules
	@echo 
	@echo '========================================================='
	@echo 
	@echo 'KLIPS26 module built successfully. '
	@echo ipsec.ko is in ${MOD26BUILDDIR}
	@echo 
	@(cd ${MOD26BUILDDIR}; ls -l ipsec.ko)
	@(cd ${MOD26BUILDDIR}; size ipsec.ko)
	@echo 
	@echo 'use make minstall as root to install it'
	@echo 
	@echo '========================================================='
	@echo 

mod26clean module26clean: 
	rm -rf ${MOD26BUILDDIR}

# module-only install, with error checks
minstall26:
	( OSMODLIB=`make -C $(KERNELSRC) -p help | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	if [ -z "$$OSMODLIB" ] ; then \
		OSMODLIB=`make -C $(KERNELSRC) -n -p modules_install | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	fi ; \
	if [ -z "$$OSMODLIB" ] ; then \
		echo "No known place to install module. Aborting." ; \
		exit 93 ; \
	fi ; \
	set -x ; \
	mkdir -p $$OSMODLIB/kernel/$(OSMOD_DESTDIR) ; \
	cp $(MOD26BUILDDIR)/ipsec.ko $$OSMODLIB/kernel/$(OSMOD_DESTDIR) ; \
	if [ -f /sbin/depmod ] ; then depmod -a ; fi; \
	if [ -n "$(OSMOD_DESTDIR)" ] ; then \
	mkdir -p $$OSMODLIB/kernel/$(OSMOD_DESTDIR) ; \
		if [ -f $$OSMODLIB/kernel/ipsec.ko -a -f $$OSMODLIB/kernel/$(OSMOD_DESTDIR)/ipsec.ko ] ; then \
			echo "WARNING: two ipsec.ko modules found in $$OSMODLIB/kernel:" ; \
			ls -l $$OSMODLIB/kernel/ipsec.ko $$OSMODLIB/kernel/$(OSMOD_DESTDIR)/ipsec.ko ; \
			exit 1; \
		fi ; \
	fi ; \
	set -x ) ;


else
module26: 
	echo 'Building in place is no longer supported. Please set MOD26BUILDDIR='
	exit 1

endif

# kernel install, with error checks
kinstall:
	rm -f out.kinstall
	>out.kinstall
	# undocumented kernel folklore: modules_install must precede install (observed on RHL8.0)
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) modules_install 2>&1 ) | tee -a out.kinstall ; \
	fi
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) install ) 2>&1 | tee -a out.kinstall
	${ERRCHECK} out.kinstall

kernelpatch2.6:
	packaging/utils/kernelpatch 2.6

kernelpatch2.4 kernelpatch:
	packaging/utils/kernelpatch 2.4

kernelpatch2.2:
	packaging/utils/kernelpatch 2.2

kernelpatch2.0:
	packaging/utils/kernelpatch 2.0

nattpatch:
	if [ -f ${KERNELSRC}/Makefile ]; then \
		${MAKE} nattpatch${KERNELREL}; \
	else	echo "Cannot determine Linux kernel version. Perhaps you need to set KERNELSRC? (eg: export KERNELSRC=/usr/src/linux-`uname -r`/)"; exit 1; \
	fi;

nattpatch2.6:
	packaging/utils/nattpatch 2.6

nattpatch2.4:
	packaging/utils/nattpatch 2.4

nattpatch2.2:
	packaging/utils/nattpatch 2.2

# take all the patches out of the kernel
# (Note, a couple of files are modified by non-patch means; they are
# included in "make backup".)
unpatch:
	@echo \"make unpatch\" is obsolete. See make unapplypatch.
	exit 1

_unpatch:
	for f in `find $(KERNELSRC)/. -name '*.preipsec' -print` ; \
	do \
		echo "restoring $$f:" ; \
		dir=`dirname $$f` ; \
		core=`basename $$f .preipsec` ; \
		cd $$dir ; \
		mv -f $$core.preipsec $$core ; \
		rm -f $$core.wipsec $$core.ipsecmd5 ; \
	done

# at the moment there is no difference between snapshot and release build
snapready:	buildready
relready:	buildready
ready:		devready

# set up for build
buildready:
	rm -f dtrmakefile cvs.datemark
	cd doc ; $(MAKE) -s

rpm:
	@echo please cd packaging/redhat and
	@echo run "make RH_KERNELSRC=/some/path/to/kernel/src rpm"

ipkg_strip:
	@echo "Minimizing size for ipkg binaries..."
	@cd $(DESTDIR)$(INC_USRLOCAL)/lib/ipsec && \
	for f in *; do (if file $$f | grep ARM > /dev/null; then ( $(STRIP) --strip-unneeded $$f); fi); done
	@rm -r $(DESTDIR)$(INC_USRLOCAL)/man
	@rm -f $(DESTDIR)$(INC_RCDEFAULT)/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/lib/ipsec/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/libexec/ipsec/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/sbin/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/share/doc/openswan/*


ipkg_module:
	@echo "Moving ipsec.o into temporary location..."
	KV=$(shell ${KVUTIL} ${KERNELSRC}/Makefile) && \
	mkdir -p $(OPENSWANSRCDIR)/packaging/ipkg/kernel-module/lib/modules/$$KV/net/ipsec
	KV=$(shell ${KVUTIL} ${KERNELSRC}/Makefile) && \
	cp ${OPENSWANSRCDIR}/modobj/ipsec.o $(OPENSWANSRCDIR)/packaging/ipkg/kernel-module/lib/modules/$$KV/net/ipsec/
	KV=$(shell ${KVUTIL} ${KERNELSRC}/Makefile)

ipkg_clean:
	rm -rf $(OPENSWANSRCDIR)/packaging/ipkg/kernel-module/
	rm -rf $(OPENSWANSRCDIR)/packaging/ipkg/ipkg/
	rm -f $(OPENSWANSRCDIR)/packaging/ipkg/control-oprnswan
	rm -f $(OPENSWANSRCDIR)/packaging/ipkg/control-openswan-module


ipkg: programs install ipkg_strip ipkg_module
	@echo "Generating ipkg..."; 
	DESTDIR=${DESTDIR} OPENSWANSRCDIR=${OPENSWANSRCDIR} ARCH=${ARCH} IPSECVERSION=${IPSECVERSION} ./packaging/ipkg/generate-ipkg


env:
	env
	exit 1

