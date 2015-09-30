#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
args="--rootdir=${ROOTDIR} --config ${ROOTDIR}/testing/pluto/xauth-pluto-03/road.conf --verbose --verbose --verbose"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args 2>&1

