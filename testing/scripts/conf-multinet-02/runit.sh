#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#          TESTDIR=    this directory (in case we got moved to object land)
#

exe=permuteconf
conf=testing/pluto/multinet-02/west.conf
args="--rootdir=${ROOTDIR}/testing/baseconfigs/all --config ${ROOTDIR}/$conf"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args

