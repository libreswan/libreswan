#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
conf=testing/pluto/multinet-01/west.conf
args="--rootdir=${ROOTDIR}/testing/baseconfigs/all --config ${ROOTDIR}/$conf --verbose --verbose --verbose"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args

