#!/bin/sh

# assumes that 
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

args="--rootdir=$ROOTDIR/testing/baseconfigs/all --config $ROOTDIR/testing/baseconfigs/west/etc/ipsec.conf --verbose --verbose"
echo "file $ROOTDIR/OBJ.linux.i386/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args $args >OUTPUT/west-flat.conf-out" >>.gdbinit

eval ${OBJDIRTOP}/programs/readwriteconf/readwriteconf $args

