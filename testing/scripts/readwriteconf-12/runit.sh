#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
conf="--config ${ROOTDIR}/testing/scripts/readwriteconf-12/gimli.conf"
args="--rootdir=${ROOTDIR}/testing/baseconfigs/all $conf --verbose --verbose"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args 2>&1

