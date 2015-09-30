#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
args="--rootdir=${ROOTDIR}/testing/baseconfigs/all --config ${ROOTDIR}/testing/pluto/sourceip-01/east.conf --verbose --verbose --verbose"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args 2>&1

