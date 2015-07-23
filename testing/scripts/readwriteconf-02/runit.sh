#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
args="--rootdir=${ROOTDIR} --config ${ROOTDIR}/testing/baseconfigs/east/etc/ipsec.conf "
#args="$args --verbose --verbose --verbose --verbose"
echo "file $exe" >.gdbinit
echo "set args $args >OUTPUT/east-flat.conf-out" >>.gdbinit

eval $exe $args 2>&1


