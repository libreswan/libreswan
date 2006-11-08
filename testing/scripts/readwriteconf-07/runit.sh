#!/bin/sh

# assumes that 
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

conf=$ROOTDIR/testing/pluto/transport-01/east.conf
rootdir="--rootdir=$ROOTDIR/testing/baseconfigs/all --rootdir2=$ROOTDIR"
echo "file $ROOTDIR/OBJ.linux.i386/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args $rootdir --config $conf --verbose --verbose >OUTPUT/transport-flat.conf-out" >>.gdbinit

eval ${OBJDIRTOP}/programs/readwriteconf/readwriteconf $rootdir --config ${conf}


