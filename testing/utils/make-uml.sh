#!/bin/sh
#
# 
# $Id: make-uml.sh,v 1.51 2005/11/21 08:44:57 mcr Exp $
#

# show me
#set -x

# fail if any command fails
set -e

case $# in
    1) OPENSWANSRCDIR=$1; shift;;
esac

CC=${CC-cc}

if [ `id -u` = 0 ]
then
    echo Do not run this as root.
    exit
fi

# we always use OBJ directories for UML builds.
export USE_OBJDIR=true

# include this dir, in particular so that we can get the local "touch"
# program.
export PATH=$OPENSWANSRCDIR/testing/utils:$PATH 


#
# configuration for this file has moved to $OPENSWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at umlsetup-sample.sh
# in this directory. Copy it to $OPENSWANSRCDIR and edit it.
#
OPENSWANSRCDIR=${OPENSWANSRCDIR-../..}
if [ ! -f ${OPENSWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in doc/umltesting.html and testing/utils/umlsetup-sample.sh.
    exit 1
fi

. ${OPENSWANSRCDIR}/umlsetup.sh
. ${OPENSWANSRCDIR}/testing/utils/uml-functions.sh

KERNVER=${KERNVER-}    

case $KERNVER in 
	26) KERNVERSION=2.6;;
	*) KERNVERSION=2.4;;
esac

echo Setting up for kernel KERNVER=$KERNVER and KERNVERSION=$KERNVERSION


# set the default for this
NATTPATCH=${NATTPATCH-true}

# make absolute so that we can reference it from POOLSPACE
OPENSWANSRCDIR=`cd $OPENSWANSRCDIR && pwd`;export OPENSWANSRCDIR

# what this script does is create some Makefile
#  (if they do not already exist)
# that will copy everything where it needs to go.

if [ -d $OPENSWANSRCDIR/testing/kernelconfigs ]
then
    TESTINGROOT=$OPENSWANSRCDIR/testing
fi
TESTINGROOT=${TESTINGROOT-/c2/freeswan/sandbox/testing}

if [ -z "$NONINTPATCH" ]
then
    if [ -f ${TESTINGROOT}/kernelconfigs/linux-${KERNVERSION}.0-nonintconfig.patch ]
    then
	NONINTPATCH=${TESTINGROOT}/kernelconfigs/linux-${KERNVERSION}.0-nonintconfig.patch
	echo "Found non-int patch $NONINTPATCH"
    else
	echo "Can not find NONINTPATCH: +$NONINTPATCH+"
	echo "Set to 'none' if it is not relevant"
	exit 1
    fi
fi

# more defaults
NONINTCONFIG=oldconfig

# hack for version specific stuff
UMLVERSION=`basename $UMLPATCH .bz2 | sed -e 's/uml-patch-//'`
EXTRAPATCH=${TESTINGROOT}/kernelconfigs/extras.$UMLVERSION.patch

# dig the kernel revision out.
KERNEL_MAJ_VERSION=`${OPENSWANSRCDIR}/packaging/utils/kernelversion-short $KERNPOOL/Makefile`


echo -n Looking for Extra patch at $EXTRAPATCH..
if [ -f "${EXTRAPATCH}" ]
then
    echo found it.
else
    echo none.
    EXTRAPATCH=
fi

mkdir -p $POOLSPACE
UMLMAKE=$POOLSPACE/Makefile
NOW=`date`
USER=${USER-`id -un`}
echo '#' built by $0 on $NOW by $USER >|$UMLMAKE
echo '#' >>$UMLMAKE

# okay, copy the kernel, apply the UML patches, and build a plain kernel.
UMLPLAIN=$POOLSPACE/plain${KERNVER}
mkdir -p $UMLPLAIN

# now, setup up root dir
NEED_plain=false

# go through each regular host and see what kernel to use, and
# see if we have to build the local plain kernel.
for host in $REGULARHOSTS
do
    kernelvar=UML_plain${KERNVER}_KERNEL
    UMLKERNEL=${!kernelvar}
    if [ -z "${UMLKERNEL}" ]
    then
	kernelvar=UML_${host}_KERNEL
	UMLKERNEL=${!kernelvar}
	if [ -z "${UMLKERNEL}" ]
	then
	    # must need stock kernel.
	    UMLKERNEL=${UMLPLAIN}/linux
	    NEED_plain=true
	fi
    fi
    echo Using kernel: $UMLKERNEL for $host

    setup_host_make $host $UMLKERNEL regular ${KERNVER} >>$UMLMAKE
done

# build a plain kernel if we need it!
if $NEED_plain && [ ! -x $UMLPLAIN/linux ]
then
    cd $UMLPLAIN
    lndir -silent $KERNPOOL .

    applypatches

    echo Copying kernel config ${TESTINGROOT}/kernelconfigs/umlplain${KERNVER}.config 
    rm -f .config
    cp ${TESTINGROOT}/kernelconfigs/umlplain${KERNVER}.config .config
    
    (make CC=${CC} ARCH=um $NONINTCONFIG && make CC=${CC} ARCH=um dep && make ARCH=um CC=${CC} linux ) || exit 1 </dev/null 
fi

BUILD_MODULES=${BUILD_MODULES-true}
if $NEED_plain
then
    :
else
    BUILD_MODULES=false
fi
    
setup_make $BUILD_MODULES >>$UMLMAKE

# now, execute the Makefile that we have created!
cd $POOLSPACE && make $REGULARHOSTS 

# now, copy the kernel, apply the UML patches.
# then, make FreeSWAN patches as well.
#
UMLSWAN=$POOLSPACE/swan${KERNVER}

# we could copy the UMLPLAIN to make this tree. This would be faster, as we
# already built most everything. We could also just use a FreeSWAN-enabled
# kernel on sunrise/sunset. We avoid this as we actually want them to always
# work.

# where to install FreeSWAN tools
DESTDIR=$POOLSPACE/root

# do not generate .depend by default
KERNDEP=''

mkdir -p $UMLSWAN

# now, setup up root dir
NEED_swan=false

# go through each regular host and see what kernel to use, and
# see if we have to build the local plain kernel.
for host in $OPENSWANHOSTS
do
    kernelvar=UML_swan${KERNVER}_KERNEL
    UMLKERNEL=${!kernelvar}
    if [ -z "${UMLKERNEL}" ]
    then
	kernelvar=UML_${host}_KERNEL
	UMLKERNEL=${!kernelvar}
	if [ -z "${UMLKERNEL}" ]
	then
	    # must need stock kernel.
	    UMLKERNEL=${UMLSWAN}/linux
	    NEED_swan=true
	fi
    fi
    echo Using kernel: $UMLKERNEL for $host

    setup_host_make $host $UMLKERNEL openswan ${KERNVER} $NEED_plain >>$UMLMAKE
done

if $NEED_swan && [ ! -x $UMLSWAN/linux ]
then
    cd $UMLSWAN
    lndir -silent $KERNPOOL .

    applypatches
    
    # copy the config file
    rm -f .config
    cp ${TESTINGROOT}/kernelconfigs/umlswan${KERNVER}.config .config

    # nuke final executable here since we will do FreeSWAN in a moment.
    rm -f linux .depend
    KERNDEP=dep

    grep CONFIG_KLIPS $UMLSWAN/.config || exit 1
fi

if $NEED_swan && [ ! -x $UMLSWAN/linux ]
then
    cd $OPENSWANSRCDIR || exit 1
 
    make KERNMAKEOPTS='ARCH=um' KERNELSRC=$UMLSWAN KERNCLEAN='' KERNDEP=$KERNDEP KERNEL=linux DESTDIR=$DESTDIR NONINTCONFIG=${NONINTCONFIG} verset kpatch rcf kernel || exit 1 </dev/null 

    # mark it as read-only, so that we don't edit the wrong files by mistake!
    find $UMLSWAN/net/ipsec $UMLSWAN/include/openswan -name '*.[ch]' -type f -print | xargs chmod a-w
fi

cd $OPENSWANSRCDIR || exit 1

make WERROR=-Werror USE_OBJDIR=true programs

# now, execute the Makefile that we have created!
cd $POOLSPACE && make $OPENSWANHOSTS 

    
#
# $Log: make-uml.sh,v $
# Revision 1.51  2005/11/21 08:44:57  mcr
# 	adjust UML to use initrd and cramfs.
#
# Revision 1.50  2005/07/27 15:51:39  mcr
# 	set up $PATH to use local touch program.
#
# Revision 1.49  2005/07/22 13:45:49  mcr
# 	make sure that UML builds are always with -Werror.
#
# Revision 1.48  2005/07/14 01:35:54  mcr
# 	use USE_OBJDIR.
#
# Revision 1.47  2005/06/06 19:53:42  mcr
# 	be a nit, and refuse to run make-uml.sh if the user
# 	is root.
# 	document the NONINTPATCH= value.
#
# Revision 1.46  2005/04/17 04:38:41  mcr
# 	mark UML source as read-only to keep us from editing it.
#
# Revision 1.45  2005/04/15 02:16:53  mcr
# 	re-factored kernel directory creation/patching to routine.
#
# Revision 1.44  2005/04/07 20:24:52  mcr
# 	make sure to include NAT-T in 2.6 plain kernel.
#
# Revision 1.43  2005/04/06 17:59:26  mcr
# 	make it easier to set UMLPATCH=none.
#
# Revision 1.42  2005/03/20 23:19:07  mcr
# 	note which thing (NONINTPATCH) it was that wasn't found.
#
# Revision 1.41  2005/02/11 01:32:23  mcr
# 	added code for a second UML patch.
#
# Revision 1.40  2004/09/06 04:47:05  mcr
# 	make sure to pass $KERNVER into setup_host_make.
#
# Revision 1.39  2004/08/22 03:31:29  mcr
# 	added -p to PATCHAPPLIED mkdir.
#
# Revision 1.38  2004/08/18 02:10:49  mcr
# 	kernel 2.6 changes.
#
# Revision 1.37  2004/08/14 03:30:15  mcr
# 	make sure to set KERNVER/KERNVERSION after umlsetup.sh.
#
# Revision 1.36  2004/08/03 23:25:34  mcr
# 	find noninteraction patch properly.
#
# Revision 1.35  2004/08/03 23:23:55  mcr
# 	set default value for NONINTCONFIG.
#
# Revision 1.34  2004/07/26 15:05:34  mcr
# 	introduce kernel versioning to the UML setup script.
#
# Revision 1.33  2004/04/03 19:44:52  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.32  2004/02/03 03:33:08  mcr
# 	apply NAT-T patch unless we are told not to (maybe it is
# 	already applied)
#
# Revision 1.31  2003/04/10 02:41:15  mcr
# 	fix location of </dev/null redirects.
#
# Revision 1.30  2003/04/09 04:21:52  build
# 	make sure that stdin is /dev/null when building kernels to
# 	keep "rm" from thinking it should prompt!
#
# Revision 1.29  2003/04/03 23:41:46  mcr
# 	note if we couldn't find a patch we were told exists
#
# Revision 1.28  2002/12/18 17:33:33  mcr
# 	apply local patches, if any are found.
#
# Revision 1.27  2002/11/11 02:44:25  mcr
# 	add ability to provide per-UML-patch patches in case we need
# 	to use a particular iteration of UML, but there are still
# 	problems with it.
#
# Revision 1.26  2002/08/26 15:37:27  mcr
# 	used wrong sense when looking for NONINTPATCH, -z is needed.
#
# Revision 1.25  2002/08/25 19:39:15  mcr
# 	added missing "then" to NONINTPATCH test.
#
# Revision 1.24  2002/08/25 17:39:45  mcr
# 	apply the RH nonint-config patch if we can find it
# 	either in $TESTINGROOT, or via $NONINTPATCH.
#
# Revision 1.23  2002/08/05 00:27:43  mcr
# 	do not install FreeSWAN for "regular hosts"
#
# Revision 1.22  2002/08/02 22:33:30  mcr
# 	call setup_make for common makefile portions.
#
# Revision 1.21  2002/07/29 02:46:09  mcr
# 	move setting of TESTINGROOT to before setup_host_make where it
# 	is in fact used.
# 	make the regular hosts after making their kernel.
#
# Revision 1.20  2002/07/29 01:02:20  mcr
# 	instead of actually doing all the operations, build
# 	a makefile in $POOLSPACE that will do it whenever necessary.
#
# Revision 1.18  2002/06/17 04:23:13  mcr
# 	make-uml.sh is mature enough to not need set -x now.
#
# Revision 1.17  2002/06/03 01:23:36  mcr
# 	added "nopromptgo" and "rcf" to provide documented "oldgo" and "ocf"
# 	functionality.
# 	"oldgo" and "ocf" now will permit interaction with the user as
# 	permitted (and undocumented) by many users.
#
# Revision 1.16  2002/04/24 07:55:32  mcr
# 	#include patches and Makefiles for post-reorg compilation.
#
# Revision 1.15  2002/04/05 01:21:39  mcr
# 	make-uml script was building statically linked FreeSWAN kernels
# 	only by fluke - turns out that "make oldconfig" blows away
# 	any options in .config that weren't defined. Thus, the initial
# 	build of a non-SWAN kernel before building FreeSWAN would
# 	blow away the CONFIG_IPSEC options- specifically the CONFIG_IPSEC=y
# 	(vs =m). This worked before because "make insert" put the
# 	options back in, but now that the default has changed to modules,
# 	the it defaults the wrong way.
# 	Solution: copy the .config file in again after the plain build.
#
# Revision 1.14  2002/04/03 23:42:18  mcr
# 	force copy of swan kernel config file to get right IPSEC=y options.
# 	redirect some build output to a local file.
#
# Revision 1.13  2002/02/16 20:56:06  rgb
# Force make programs so UML does not depend on top level make programs.
#
# Revision 1.12  2002/02/13 21:39:16  mcr
# 	change to use uml*.config files instead.
# 	uml*.config files have been updated for 2.4.7-10 UML patch.
#
# Revision 1.11  2002/01/11 05:26:03  rgb
# Fixed missing semicolon bug.
#
# Revision 1.10  2001/11/27 05:36:30  mcr
# 	just look for a kernel in build directory. This
# 	type of "optomization" is dumb - it should be a makefile.
#
# Revision 1.9  2001/11/23 00:36:01  mcr
# 	take $FREESWANDIR as command line argument.
# 	use HS's "devready" instead of fudging our own.
#
# Revision 1.8  2001/11/22 05:46:07  henry
# new version stuff makes version.c obsolete
#
# Revision 1.7  2001/11/07 20:10:20  mcr
# 	revised setup comments after RGB consultation.
# 	removed all non-variables from umlsetup-sample.sh.
#
# Revision 1.6  2001/11/07 19:25:17  mcr
# 	split out some functions from make-uml.
#
# Revision 1.5  2001/10/28 23:52:22  mcr
# 	pathnames need to be fully qualified.
#
# Revision 1.4  2001/10/23 16:32:08  mcr
# 	make log files unique to each UML.
#
# Revision 1.3  2001/10/15 05:41:46  mcr
# 	moved variables for UML setup to common file.
# 	provided sample of this file.
#
# Revision 1.2  2001/09/25 01:09:53  mcr
# 	some minor changes to whether to run "KERNDEP"
#
# Revision 1.1  2001/09/25 00:52:16  mcr
# 	a script to build a UML+FreeSWAN testing environment.
#
#    
