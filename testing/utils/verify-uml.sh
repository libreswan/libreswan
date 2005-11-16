#!/bin/sh

# show me
#set -x

# fail if any command fails
set -e

case $# in
    1) OPENSWANSRCDIR=$1; shift;;
esac

if [ `id -u` = 0 ]
then
    echo Do not run this as root.
    exit
fi

#
# configuration for this file has moved to $OPENSWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at umlsetup-sample.sh
# in this directory. Copy it to $OPENSWANSRCDIR and edit it.
#
if [ -z "${OPENSWANSRCDIR}" ] && [ -f umlsetup.sh ]
then
    OPENSWANSRCDIR=`pwd`
fi

OPENSWANSRCDIR=${OPENSWANSRCDIR-../..}
if [ ! -f ${OPENSWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in doc/umltesting.html and testing/utils/umlsetup-sample.sh.
    exit 1
fi

. ${OPENSWANSRCDIR}/umlsetup.sh

if [ ! -d ${KERNPOOL}/. ]; then echo Your KERNPOOL= is not properly set; exit 1; fi	

if [ ! -r ${UMLPATCH} ]; then echo Your UMLPATCH= is not properly set; exit 1; fi
if [ -z "${OPENSWANHOSTS}" ]; then echo Your OPENSWANHOSTS= is not properly set; exit 1; fi
if [ -z "${NATTPATCH}" ]; then echo Your NATTPATCH= is not properly set; exit 1; fi 
if [ ! -d ${BASICROOT}/. ]; then echo Your BASICROOT= is not properly set; exit 1; fi
    
#
# $Log: verify-uml.sh,v $
# Revision 1.1  2005/07/14 01:37:56  mcr
# 	script to check out umlsetup.sh and complain before
# 	we get too far.
#
#
#    
