#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
conf="--config ${ROOTDIR}/testing/scripts/readwriteconf-24/ipv6.conf"
args="--rootdir=${ROOTDIR}/testing/scripts/readwriteconf-24 $conf "
#args="$args --verbose --verbose --verbose --verbose"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args 2>&1

