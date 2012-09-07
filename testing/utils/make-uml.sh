#!/bin/bash
#

# show me
set -x

# fail if any command fails
set -e

case $# in
    1) LIBRESWANSRCDIR=$1; shift;;
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
export PATH=$LIBRESWANSRCDIR/testing/utils:$PATH 


#
# configuration for this file has moved to $LIBRESWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at umlsetup-sample.sh
# in this directory. Copy it to $LIBRESWANSRCDIR and edit it.
#
LIBRESWANSRCDIR=${LIBRESWANSRCDIR-../..}
if [ ! -f ${LIBRESWANSRCDIR}/umlsetup.sh ]
then
    echo >&2 "make-uml.sh: Error: No umlsetup.sh configuration file in LIBRESWANSRCDIR=\"${LIBRESWANSRCDIR}\"."
    echo >&2 "    Please read instructions in doc/umltesting.html and testing/utils/umlsetup-sample.sh."
    exit 1
fi

. ${LIBRESWANSRCDIR}/umlsetup.sh
. ${LIBRESWANSRCDIR}/testing/utils/uml-functions.sh

KERNVER=${KERNVER-}    

case $KERNVER in 
	26) KERNVERSION=2.6;;
	*) KERNVERSION=2.4;;
esac

echo Setting up for kernel KERNVER=$KERNVER and KERNVERSION=$KERNVERSION


# set the default for these
NATTPATCH=${NATTPATCH:-false}
SAREFPATCH=${SAREFPATCH:-false}

# make absolute so that we can reference it from POOLSPACE
LIBRESWANSRCDIR=`cd $LIBRESWANSRCDIR && pwd`;export LIBRESWANSRCDIR

# what this script does is create some Makefile
#  (if they do not already exist)
# that will copy everything where it needs to go.

if [ -d $LIBRESWANSRCDIR/testing/kernelconfigs ]
then
    TESTINGROOT=$LIBRESWANSRCDIR/testing
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
KERNEL_MAJ_VERSION=`${LIBRESWANSRCDIR}/packaging/utils/kernelversion-short $KERNPOOL/Makefile`


echo -n Looking for Extra patch at $EXTRAPATCH..
if [ -f "${EXTRAPATCH}" ]
then
    echo found it.
else
    echo none.
    EXTRAPATCH=
fi

mkdir -p $POOLSPACE
retval=$?
if test ${retval} -ne 0 ; then
	echo >&2 "Error: could not create POOLSPACE=\"${POOLSPACE}\";, mkdir returned ${retval} from make-uml.sh:${LINENO}"
	exit ${retval}
fi

if [ ! -d ${LIBRESWANSRCDIR}/UMLPOOL/. ]; then ln -s $POOLSPACE ${LIBRESWANSRCDIR}/UMLPOOL; fi

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

    lndirkerndirnogit $KERNPOOL .

    applypatches
    sed -i 's/EXTRAVERSION =.*$/EXTRAVERSION =plain/' Makefile
    PLAINKCONF=${TESTINGROOT}/kernelconfigs/umlnetkey${KERNVER}.config
    echo "make-uml.sh: Using \"${PLAINKCONF}\" to build a new plain kernel"
    ( ${MAKE:-make} CC=${CC} ARCH=um allnoconfig KCONFIG_ALLCONFIG=${PLAINKCONF} INSTALL_MOD_PATH=${BASICROOT}/ linux modules modules_install ) || exit 1 </dev/null
fi

UMLNETKEY=$POOLSPACE/netkey${KERNVER}
mkdir -p $UMLNETKEY
NETKEYKERNEL=$UMLNETKEY/linux

if [ ! -x $NETKEYKERNEL ] 
  then
   cd $UMLNETKEY

    lndirkerndirnogit $KERNPOOL .

    applypatches
    sed -i 's/EXTRAVERSION =.*$/EXTRAVERSION =netkey/' Makefile 
    NETKEYCONF=${TESTINGROOT}/kernelconfigs/umlnetkey${KERNVER}.config
    echo "using $NETKEYCONF to build netkey kernel"
     (make CC=${CC} ARCH=um allnoconfig KCONFIG_ALLCONFIG=$NETKEYCONF INSTALL_MOD_PATH=${BASICROOT}/ ARCH=um linux modules modules_install) || exit 1 </dev/null
fi

UMLFEDORA=$POOLSPACE/fedora${KERNVER}
mkdir -p $UMLFEDORA
FEDORAKERNEL=$UMLFEDORA/linux

if [ ! -x $FEDORAKERNEL ] 
  then
   cd $UMLFEDORA

    lndirkerndirnogit $KERNPOOL .

    applypatches
    sed -i 's/EXTRAVERSION =.*$/EXTRAVERSION =fedora/' Makefile 
    FEDORACONF=${TESTINGROOT}/kernelconfigs/umlfedora${KERNVER}.config
    echo "using $FEDORACONF to build fedora kernel"
     (make CC=${CC} ARCH=um allnoconfig KCONFIG_ALLCONFIG=$FEDORACONF INSTALL_MOD_PATH=${BASICROOT}/ ARCH=um linux modules modules_install) || exit 1 </dev/null
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
echo "info: make-uml.sh:${LINENO} in `pwd`"
echo " aand MAKE=${MAKE}"
MAKE_DEBUG="--debug=b";
${MAKE:-make} ${MAKE_DEBUG} -C ${POOLSPACE}   ${REGULARHOSTS}

# now, copy the kernel, apply the UML patches.
# then, make Libreswan patches as well.
#
UMLSWAN=$POOLSPACE/swan${KERNVER}

# we could copy the UMLPLAIN to make this tree. This would be faster, as we
# already built most everything. We could also just use a Libreswan-enabled
# kernel on sunrise/sunset. We avoid this as we actually want them to always
# work.

# where to install Libreswan tools
DESTDIR=$POOLSPACE/root

# do not generate .depend by default
KERNDEP=''

mkdir -p $UMLSWAN

# now, setup up root dir
NEED_swan=false

# go through each regular host and see what kernel to use, and
# see if we have to build the local plain kernel.
for host in $LIBRESWANHOSTS
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

    setup_host_make $host $UMLKERNEL libreswan ${KERNVER} $NEED_plain $NETKEYKERNEL $FEDORAKERNEL >>$UMLMAKE
done

if $NEED_swan && [ ! -x $UMLSWAN/linux ]
then
    cd $UMLSWAN
    lndirkerndirnogit $KERNPOOL .

    applypatches
    sed -i 's/EXTRAVERSION =.*$/EXTRAVERSION =klips/' Makefile 

    # looks like applypatches does not patch in klips - make line changed from the old one in commit b195c03ff554 as it built kernel and modules too
    cd $LIBRESWANSRCDIR || exit 1
    (make KERNMAKEOPTS='ARCH=um' KERNELSRC=$UMLSWAN KERNCLEAN='' KERNDEP=$KERNDEP KERNEL=linux DESTDIR=$DESTDIR NONINTCONFIG=${NONINTCONFIG} verset kpatch rcf) || exit 1
    cd $UMLSWAN || exit 1

    # copy the config file
    rm -f .config
    #cp ${TESTINGROOT}/kernelconfigs/umlswan${KERNVER}.config .config
    KLIPSKCONF=${TESTINGROOT}/kernelconfigs/umlswan${KERNVER}.config
    echo "using $KLIPSKCONF to build umlswan kernel"
    (make CC=${CC} ARCH=um allnoconfig KCONFIG_ALLCONFIG=$KLIPSKCONF INSTALL_MOD_PATH=${BASICROOT}/ linux modules modules_install) || exit 1 </dev/null

    echo "Confirming KLIPS is compiled into the UMLSWAN kernel..."
    grep CONFIG_KLIPS $UMLSWAN/.config || exit 1
fi

cd $LIBRESWANSRCDIR || exit 1

make ${WERROR:-WERROR=-Werror} USE_OBJDIR=true USE_IPSECPOLICY=true programs

# now, execute the Makefile that we have created!
cd $POOLSPACE && make $LIBRESWANHOSTS 

echo "###  bottom exiting make-umls.sh running at pwd: `pwd`"

