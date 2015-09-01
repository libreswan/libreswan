#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

args="--rootdir=${ROOTDIR} --config $ROOTDIR/testing/baseconfigs/west/etc/ipsec.conf --verbose --verbose"
#args="$args --verbose --verbose"
echo "file $ROOTDIR/OBJ.linux.$(arch)/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args $args >OUTPUT/west-flat.conf-out" >>.gdbinit

eval ${OBJDIRTOP}/programs/readwriteconf/readwriteconf $args 2>&1


