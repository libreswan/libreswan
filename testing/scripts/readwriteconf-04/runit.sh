#!/bin/sh

# assumes that 
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
args="--rootdir=${ROOTDIR}/testing/baseconfigs/all --config ${ROOTDIR}/testing/pluto/aggr-pluto-01/east.conf"
echo "file $exe" >.gdbinit
echo "set args $args >OUTPUT/east-flat.conf-out" >>.gdbinit

eval $exe $args 

