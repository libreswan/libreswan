#! /bin/sh 
#
# 
# $Id: uml-functions.sh,v 1.45 2005/11/21 08:44:57 mcr Exp $
#

setup_make() {
    domodules=$1

    TAB="	@"
    depends=""

    echo "# RULES for making module"

    # figure out our base architecture, as we'll need in the Makefiles.
    SUBARCH=${ARCH-`uname -m`}
    case $SUBARCH in
	i?86) SUBARCH=i386;;
    esac

    echo "IPSECDIR=${OPENSWANSRCDIR}/linux/net/ipsec"
    echo "USE_OBJDIR=${USE_OBJDIR}"
    echo "OPENSWANSRCDIR=${OPENSWANSRCDIR}"
    echo "include ${OPENSWANSRCDIR}/Makefile.inc"
    echo "include ${OPENSWANSRCDIR}/Makefile.ver"
    echo 
    
    echo "all: "
    echo "$TAB echo Default make called"
    echo "$TAB exit 1"
    echo

    if $domodules
    then
	echo "module/ipsec.o: ${OPENSWANSRCDIR}/packaging/makefiles/module.make \${IPSECDIR}/*.c"
	echo "$TAB mkdir -p module"
	echo "$TAB make -C ${OPENSWANSRCDIR} OPENSWANSRCDIR=${OPENSWANSRCDIR} MODBUILDDIR=$POOLSPACE/module MODBUILDDIR=$POOLSPACE/module KERNELSRC=$UMLPLAIN ARCH=um SUBARCH=${SUBARCH} module "
	echo

	echo "module26/ipsec.ko: ${OPENSWANSRCDIR}/packaging/makefiles/module26.make \${IPSECDIR}/*.c"
	echo "$TAB mkdir -p module26"
	echo "$TAB make -C ${OPENSWANSRCDIR} OPENSWANSRCDIR=${OPENSWANSRCDIR} MODBUILDDIR=$POOLSPACE/module MOD26BUILDDIR=$POOLSPACE/module26 KERNELSRC=$UMLPLAIN ARCH=um SUBARCH=${SUBARCH} module26 "
	echo
    fi

    # now describe how to build the initrd.
    echo "initrd.uml: ${OPENSWANSRCDIR}/testing/utils/initrd.list"
    echo "$TAB fakeroot ${OPENSWANSRCDIR}/testing/utils/buildinitrd ${OPENSWANSRCDIR}/testing/utils/initrd.list ${OPENSWANSRCDIR} ${BASICROOT}" 
}

# output should directed to a Makefile
setup_host_make() {
    host=$1
    KERNEL=$2
    HOSTTYPE=$3
    KERNVER=$4
    domodules=$5          # true or false
    KERNDIR=`dirname $KERNEL`
    TAB="	@"
    hostroot=$host/root
    depends=""

    echo "# RULES for host $host"
    echo 

    echo "$hostroot:"
    echo "$TAB mkdir -p $host $hostroot"
    echo
    depends="$depends $host/root"

    echo "# make a hard link copy of the ROOT, but"
    echo "# make private copy of /var."
    echo "$hostroot/sbin/init : ${BASICROOT}/sbin/init"
    echo "$TAB -(cd ${BASICROOT} && find . -print | cpio -pld $POOLSPACE/$hostroot 2>/dev/null )"
    echo "$TAB rm -rf $hostroot/var"

    echo "$TAB (cd ${BASICROOT} && find var -print | cpio -pd $POOLSPACE/$hostroot 2>/dev/null )"

    # make sure that we have /dev, /tmp and /var/run
    echo "$TAB mkdir -p $hostroot/dev $hostroot/tmp $hostroot/var/run $hostroot/usr/share $hostroot/proc $hostroot/var/log/pluto/peer"
    echo "$TAB rm -f $hostroot/dev/console $hostroot/dev/null"
    echo "$TAB touch $hostroot/dev/console $hostroot/dev/null"

    # root image may be debian, but we expect rh-style /etc/rc.d
    echo "$TAB mkdir -p $hostroot/etc/rc.d"
    echo "$TAB mkdir -p $hostroot/testing $hostroot/usr/src $hostroot/usr/obj"
    echo "$TAB if [ ! -d $hostroot/etc/rc.d/init.d ]; then (cd $hostroot/etc/rc.d && ln -fs ../init.d ../rc?.d . ); fi"

    # nuke certain other files that get in the way of booting
    echo "$TAB rm -f $hostroot/etc/mtab $hostroot/sbin/hwclock"

    # set up the timezone
    echo "$TAB rm -f $hostroot/etc/localtime "

    # dummy out fsck.
    echo "$TAB ln -f $hostroot/bin/true $hostroot/sbin/fsck.hostfs"

    # force it to GMT, otherwise (RH7.1) use host's zoneinfo.
    if [ -f /usr/share/zoneinfo/GMT ] 
    then
      echo "$TAB cp /usr/share/zoneinfo/GMT $hostroot/etc/localtime"
    else
      echo "$TAB cp /etc/localtime $hostroot/etc/localtime"
    fi

    # now remove any files that we shouldn't have copied.
    echo "$TAB (cd ${TESTINGROOT}/baseconfigs/all && find . -type f -print) | (cd $hostroot && xargs rm -f)"
    echo "$TAB (cd ${TESTINGROOT}/baseconfigs/$host && find . -type f -print) | (cd $hostroot && xargs rm -f)"
    # okay, that's all the stock stuff
    echo 
    depends="$depends $hostroot/sbin/init"

    # copy global configuration files, and make sure that they are up-to-date.
    (cd ${TESTINGROOT}/baseconfigs/all && find . -type f -print) | sed -e 's,^\./,,' >makeuml.$$
    echo -n >makeuml2.$$
    cat makeuml.$$ | while read file
    do
        case $file in
	    *~) ;;
	    *CVS/*);;
	    */.\#*);;
	    etc/fstab);;
	    *) echo "$hostroot/$file : ${TESTINGROOT}/baseconfigs/all/$file $hostroot"
	       echo "$TAB rm -f $hostroot/$file && mkdir -p `dirname $hostroot/$file` && cp ${TESTINGROOT}/baseconfigs/all/$file $hostroot/$file"
	       echo
	       echo -n $hostroot/$file ' ' >>makeuml2.$$
	esac
    done	 
    nicelists=`cat makeuml2.$$`
    depends="$depends $nicelists"
    rm -f makeuml.$$ makeuml2.$$

    # copy configuration files, but make sure that they are up-to-date.
    (cd ${TESTINGROOT}/baseconfigs/$host && find . -type f -print) | sed -e 's,^\./,,'  >makeuml.$$
    echo -n >makeuml2.$$
    cat makeuml.$$ | while read file
    do
        case $file in
	    *~) ;;
	    *CVS/*);;
	    etc/fstab);;
	    */.\#*);;
	    *) echo "$hostroot/$file : ${TESTINGROOT}/baseconfigs/$host/$file $hostroot"
	       echo "$TAB rm -f $hostroot/$file && mkdir -p `dirname $hostroot/$file` && cp ${TESTINGROOT}/baseconfigs/$host/$file $hostroot/$file"
	       echo
	       echo -n $hostroot/$file ' ' >>makeuml2.$$
	esac
    done	 
 
    nicelists=`cat makeuml2.$$`
    depends="$depends $nicelists"
    rm -f makeuml.$$ makeuml2.$$

    # setup the mount of /usr/share
    echo "$hostroot/etc/fstab : ${TESTINGROOT}/baseconfigs/$host/etc/fstab"
    echo "$TAB cp ${TESTINGROOT}/baseconfigs/$host/etc/fstab $hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/share		     hostfs   defaults,ro,$SHAREROOT 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /testing		     hostfs   defaults,ro,${TESTINGROOT} 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/src		     hostfs   defaults,ro,${OPENSWANSRCDIR} 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/obj		     hostfs   defaults,ro,\${OBJDIRTOP} 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/local		     hostfs   defaults,rw,${POOLSPACE}/${hostroot}/usr/local 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /var/tmp		     hostfs   defaults,rw,${POOLSPACE}/${hostroot}/var/tmp 0 0 >>$hostroot/etc/fstab"
    depends="$depends $hostroot/etc/fstab"

    # split Debian "interfaces" file into RH ifcfg-* file
    echo "$hostroot/etc/sysconfig/network-scripts/ifcfg-eth0: $hostroot/etc/network/interfaces"
    echo "$TAB mkdir -p $hostroot/etc/sysconfig/network-scripts"
    echo "$TAB ${TESTINGROOT}/utils/interfaces2ifcfg.pl $hostroot/etc/network/interfaces $hostroot/etc/sysconfig/network-scripts"
    echo
    depends="$depends $hostroot/etc/sysconfig/network-scripts/ifcfg-eth0"

    if [ "X$HOSTTYPE" == "Xopenswan" ]
    then
	# install FreeSWAN if appropriate.
        
	echo "$hostroot/usr/local/sbin/ipsec : ${OPENSWANSRCDIR}/Makefile.inc ${OPENSWANSRCDIR}/Makefile.ver"
	echo "$TAB cd ${OPENSWANSRCDIR} && make DESTDIR=$POOLSPACE/$hostroot USE_OBJDIR=true install"
	echo
	depends="$depends $hostroot/usr/local/sbin/ipsec"

	case ${KERNVER} in
	    26) DOTO=".ko";;
	    *) DOTO=".o";;
	esac

	if $domodules
	then
	    # update the module, if any.
	    echo "$hostroot/ipsec.o : module${KERNVER}/ipsec${DOTO} $hostroot"
	    echo "$TAB -cp module${KERNVER}/ipsec${DOTO} $hostroot/ipsec.o"
	    echo
	    depends="$depends $hostroot/ipsec.o"

	    # make module startup script
	    startscript=$POOLSPACE/$host/startmodule.sh
	    echo "$startscript : $OPENSWANSRCDIR/umlsetup.sh $hostroot/ipsec.o initrd.uml"
	    echo "$TAB echo '#!/bin/sh' >$startscript"
	    echo "$TAB echo ''          >>$startscript"
	    echo "$TAB echo '# get $net value from baseconfig'          >>$startscript"
	    echo "$TAB echo . ${TESTINGROOT}/baseconfigs/net.$host.sh   >>$startscript"
	    echo "$TAB echo ''          >>$startscript"
	    echo "$TAB # the umlroot= is a local hack >>$startscript"
	    echo "$TAB echo '$POOLSPACE/plain${KERNVER}/linux initrd=$POOLSPACE/initrd.uml umlroot=$POOLSPACE/$hostroot root=/dev/ram0 rw ssl=pty umid=$host \$\$net \$\$UML_DEBUG_OPT \$\$UML_"${host}"_OPT  init=/linuxrc gim\$\$*' >>$startscript"
	    echo "$TAB chmod +x $startscript"
	    echo
	    depends="$depends $startscript"
	fi
    fi

    # make startup script
    startscript=$POOLSPACE/$host/start.sh
    echo "$startscript : $OPENSWANSRCDIR/umlsetup.sh initrd.uml"
    echo "$TAB echo '#!/bin/sh' >$startscript"
    echo "$TAB echo ''          >>$startscript"
    echo "$TAB echo '# get $net value from baseconfig'          >>$startscript"
    echo "$TAB echo . ${TESTINGROOT}/baseconfigs/net.$host.sh   >>$startscript"
    echo "$TAB echo ''          >>$startscript"
    echo "$TAB # the umlroot= is a local hack >>$startscript"
    echo "$TAB echo '$KERNEL initrd=$POOLSPACE/initrd.uml umlroot=$POOLSPACE/$hostroot root=/dev/ram0 rw ssl=pty umid=$host \$\$net \$\$UML_DEBUG_OPT \$\$UML_"${host}"_OPT  init=/linuxrc \$\$*' >>$startscript"
    echo "$TAB echo 'if [ -n \"\$\$UML_SLEEP\" ]; then eval \$\$UML_SLEEP; fi'  >>$startscript"
    echo "$TAB chmod +x $startscript"
    echo
    depends="$depends $startscript"

    echo "$host : $depends"
    echo "$TAB for dir in ${UML_extra_DIRS-x}; do (if [ -d \$\$dir ]; then echo installing in \$\$dir; cd \$\$dir && make DESTDIR=$POOLSPACE/$hostroot install; fi); done;"
    echo
}

setup_host() {
    host=$1
    KERNEL=$2
    KERNDIR=`dirname $KERNEL`

    hostroot=$POOLSPACE/$host/root
    mkdir -p $hostroot
    # copy (with hard links) 
    (cd ${BASICROOT} && find . -print | cpio -pld $hostroot 2>/dev/null )

    # make private copy of /var.
    rm -rf $hostroot/var
    (cd ${BASICROOT} && find var -print | cpio -pd $hostroot 2>/dev/null )

    # make sure that we have /dev, /tmp and /var/run
    mkdir -p $hostroot/dev $hostroot/tmp $hostroot/var/run $hostroot/usr/share $hostroot/proc

    # root image is debian, but FreeSWAN expects redhat
    mkdir -p $hostroot/etc/rc.d
    if [ ! -d $hostroot/etc/rc.d/init.d ]
    then
      (cd $hostroot/etc/rc.d && ln -fs ../init.d ../rc?.d . )
    fi
    
    # nuke certain other files that get in the way of booting
    rm -f $hostroot/etc/mtab
    rm -f $hostroot/sbin/hwclock

    # set up the timezone
    rm -f $hostroot/etc/localtime 

    # dummy out fsck.
    ln -f $hostroot/bin/true $hostroot/sbin/fsck.hostfs

    # force it to GMT, otherwise (RH7.1) use host's zoneinfo.
    if [ -f /usr/share/zoneinfo/GMT ] 
    then
      cp /usr/share/zoneinfo/GMT $hostroot/etc/localtime
    else
      cp /etc/localtime $hostroot/etc/localtime
    fi

    # or, you might want to force it to local
    # cp /etc/localtime $hostroot/etc/localtime

    # copy configuration files
    ### XXX this should be done with a generated Makefile.
    (cd ${TESTINGROOT}/baseconfigs/$host && tar cf - .) | (cd $hostroot && tar -x -f - --unlink-first)

    # setup the mount of /usr/share
    echo "none	   /usr/share		     hostfs   defaults,ro,$SHAREROOT 0 0" >>$hostroot/etc/fstab

    # split Debian "interfaces" file into RH ifcfg-* file
    mkdir -p $hostroot/etc/sysconfig/network-scripts
    ${TESTINGROOT}/utils/interfaces2ifcfg.pl $hostroot/etc/network/interfaces $hostroot/etc/sysconfig/network-scripts

    # make startup script
    startscript=$POOLSPACE/$host/start.sh
    if [ ! -f $startscript ]
    then
	echo '#!/bin/sh' >$startscript
	echo ''          >>$startscript
	echo '# get $net value from baseconfig'          >>$startscript
	echo ". ${TESTINGROOT}/baseconfigs/net.$host.sh" >>$startscript
	echo ''          >>$startscript
	echo "$KERNEL ubd0=$hostroot umid=$host \$net \$UML_DEBUG_OPT \$UML_$host_OPT \$*" >>$startscript
	chmod +x $startscript
    fi
}

applypatches() {
    if [ ! -d arch/um/.PATCHAPPLIED ] 
    then
	echo Applying $UMLPATCH

	if [ "$UMLPATCH" != "none" ] && [ "$UMLPATCH" != /dev/null ]
	then
	    if bzcat $UMLPATCH | patch -p1 
	    then
		:
	    else
		echo "Failed to apply UML patch: $UMLPATCH"
		exit 1;
	    fi
        fi

	if [ -n "$UMLPATCH2" ] && [ -f $UMLPATCH2 ]
	then
		echo Applying $UMLPATCH2
		if bzcat $UMLPATCH2 | patch -p1 
		then
		    :
		else
		    echo "Failed to apply UML patch: $UMLPATCH2"
		    exit 1;
		fi
	fi

	if [ -n "$NONINTPATCH" ] && [ "$NONINTPATCH" != "none" ]
	then
	    if [ -f "$NONINTPATCH" ]
	    then
		echo Applying non-interactive config patch
		cat $NONINTPATCH | patch -p1
		NONINTCONFIG=oldconfig_nonint
	    else
		echo Can not find +$NONINTPATCH+
		exit 1
	    fi
	fi

	if [ -n "$EXTRAPATCH" ]
	then
	    echo Applying other version specific stuff
	    cat $EXTRAPATCH | patch -p1
	fi

	for patch in ${TESTINGROOT}/kernelconfigs/local_${KERNEL_MAJ_VERSION}_*.patch
	do
	    if [ -f $patch ] 
	    then
		echo Applying local patch $patch
		cat $patch | patch -p1
	    fi
	done
	mkdir -p arch/um/.PATCHAPPLIED

	if $NATTPATCH
	then
	    echo Applying the NAT-Traversal patch
	    (cd $OPENSWANSRCDIR && make nattpatch${KERNVERSION} ) | patch -p1
	else
            echo Not applying the NAT-Traversal patch
	fi
    fi
}

#
# $Log: uml-functions.sh,v $
# Revision 1.45  2005/11/21 08:44:57  mcr
# 	adjust UML to use initrd and cramfs.
#
# Revision 1.44  2005/11/08 19:21:15  mcr
# 	add OPENSWANSRCDIR= to generated makefile.
#
# Revision 1.43  2005/09/28 12:51:59  mcr
# 	added /usr/obj mount point.
#
# Revision 1.42  2005/09/14 14:47:30  mcr
# 	create /dev/console and /dev/null so that 2.6.12 (no devfs) will
# 	work right.
#
# Revision 1.41  2005/08/31 03:36:15  mcr
# 	fixed quoting of $SLEEP, rename to UML_SLEEP.
# 	rm kernel before we copy it, in case it is being used.
#
# Revision 1.40  2005/08/14 21:38:50  mcr
# 	include ssl=pty to get serial ports onto pty's
# 	for gdbserver use.
#
# Revision 1.39  2005/07/25 19:15:44  mcr
# 	fix generate of start.sh, to properly expand SLEEP.
#
# Revision 1.38  2005/07/14 01:35:54  mcr
# 	use USE_OBJDIR.
#
# Revision 1.37  2005/05/11 02:17:52  mcr
# 	add option to sleep at end of UML run.
#
# Revision 1.36  2005/04/15 02:16:53  mcr
# 	re-factored kernel directory creation/patching to routine.
#
# Revision 1.35  2004/10/17 17:38:35  mcr
# 	add /usr/local and /var/tmp mounts to /etc/fstab so that
# 	they can be umount'ed/mount'ed to flush changes.
#
# Revision 1.34  2004/09/13 02:27:42  mcr
# 	install klips26 module as ipsec.o, not ipsec.ko.
#
# Revision 1.33  2004/09/06 18:39:45  mcr
# 	copy/rename the .ko file to ipsec.o.
#
# Revision 1.32  2004/09/06 04:49:42  mcr
# 	make sure to copy the right module into the UML root.
#
# Revision 1.31  2004/08/18 02:11:08  mcr
# 	kernel 2.6 changes.
#
# Revision 1.30  2004/04/03 19:44:52  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.29  2003/10/31 02:43:34  mcr
# 	pull up of port-selector tests
#
# Revision 1.28.2.1  2003/10/29 02:11:00  mcr
# 	make sure that local module makefile gets version info included.
#
# Revision 1.28  2003/09/02 19:45:48  mcr
# 	use rootfs= directive instead of ubd0= directive for
# 	setting hostfs root file system.
#
# Revision 1.27  2003/07/30 16:46:57  mcr
# 	created /var/log/pluto/peer directory in UMLs.
#
# Revision 1.26  2003/06/22 21:53:53  mcr
# 	generated makefile list had $hostroot missing, put it in with
# 	a more obvious way.
#
# Revision 1.25  2003/06/22 21:41:05  mcr
# 	while the file targets themselves were sanitized, the list of
# 	targets was not sanitized by the same process, and so got out
# 	of sync - it left in CVS backups. Now use the same process.
# 	Problem discovered by DHR in week of 2003/06/17.
#
# Revision 1.24  2002/11/11 17:07:18  mcr
# 	ignore CVS backup files.
#
# Revision 1.23  2002/10/30 05:00:35  rgb
# Added missing escape to catch litteral "." followed by "/" rather than
# "any char" followed by "/".
#
# Revision 1.22  2002/10/26 15:10:39  mcr
# 	make sure that all files are in the dependancy list.
#
# Revision 1.21  2002/10/22 01:13:49  mcr
# 	UML root file system will copy files from "all" config
# 	and then files from specific hosts.
#
# Revision 1.20  2002/10/17 02:39:53  mcr
# 	make sure to set SUBARCH for module builds.
#
# Revision 1.19  2002/10/02 02:18:29  mcr
# 	con=pts was not a good idea - it isn't harmless for 2.4.18.
#
# Revision 1.18  2002/09/30 16:04:29  mcr
# 	include "con=pts" for 2.4.19 UMLs.
#
# Revision 1.17  2002/09/16 18:23:58  mcr
# 	make the installed UML copy of FreeSWAN depend upon
# 	Makefile.ver as well.
#
# Revision 1.16  2002/08/29 23:47:09  mcr
# 	when generating UMLPOOL/Makefile, make sure that the generated
# 	ipsec.o depends upon the KLIPS source code
#
# Revision 1.15  2002/08/08 01:53:36  mcr
# 	when building the UML environment, make the $OPENSWANSRCDIR
# 	available as /usr/src, and the $OPENSWANSRCDIR/testing as /testing.
#
# Revision 1.14  2002/08/05 00:17:45  mcr
# 	do not install FreeSWAN for "regular hosts"
#
# Revision 1.13  2002/08/02 22:33:06  mcr
# 	create startmodule.sh that uses UMLPOOL/plain.
# 	copy ipsec.o module from UMLPOOL/module.
# 	build UMLPOOL/module/ipsec.o in common section.
#
# Revision 1.12  2002/07/29 15:47:21  mcr
# 	copying of BASICROOT often results in an error, which can be
# 	ignored.
# 	ignore CVS directories more carefully.
#
# Revision 1.11  2002/07/29 05:58:58  mcr
# 	generated UMLPOOL/Makefile now installs FreeSWAN as well.
#
# Revision 1.10  2002/07/29 05:52:31  mcr
# 	more adjusting of quoting - lost $* on end of command line.
# 	this is needed so that klipstest can invoke "east single"
#
# Revision 1.9  2002/07/29 05:46:42  mcr
# 	quiet the make output with @ on every line.
# 	the depends list does not get updated in a subshell, so
# 	reprocess it again.
# 	adjust quoting for start.sh script...
#
# Revision 1.8  2002/07/29 02:46:58  mcr
# 	make sure that the directories are made before they are used.
# 	remove ./ from file names so that dependancies find the right file.
#
# Revision 1.7  2002/07/29 01:02:20  mcr
# 	instead of actually doing all the operations, build
# 	a makefile in $POOLSPACE that will do it whenever necessary.
#
# Revision 1.6  2002/07/15 09:58:14  mcr
# 	removed ubd1 from /etc/fstab, and command line.
# 	add /usr/share mount to /etc/fstab post-copy.
#
# Revision 1.5  2002/04/04 00:19:02  mcr
# 	when setting up root file systems, see if we built an ipsec.o
# 	as part of the kernel build, and if so, copy it to /ipsec.o for
# 	later use.
#
# Revision 1.4  2002/01/12 02:50:29  mcr
# 	when removing /var to make private copy, make sure that
# 	-f(orce) is set.
#
# Revision 1.3  2001/11/23 00:38:41  mcr
# 	make /var private
# 	make fake fsck.hostfs
# 	split Debian interfaces file into RH file using script.
#
# Revision 1.2  2001/11/07 20:10:20  mcr
# 	revised setup comments after RGB consultation.
# 	removed all non-variables from umlsetup-sample.sh.
#
# Revision 1.1  2001/11/07 19:25:17  mcr
# 	split out some functions from make-uml.
#
#


