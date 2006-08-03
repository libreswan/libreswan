#!/bin/sh

# assumes that 
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
args="--rootdir=${ROOTDIR}/testing/baseconfigs/all --config ${ROOTDIR}/testing/baseconfigs/east/etc/ipsec.conf"
echo "file $exe" >.gdbinit
echo "set args $args >OUTPUT/west-flat.conf-out" >>.gdbinit

eval $exe $args 


