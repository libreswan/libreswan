#!/bin/sh

# assumes that
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

conf=$ROOTDIR/testing/pluto/transport-01/east.conf
args="--rootdir=${ROOTDIR} --rootdir2=$ROOTDIR"
echo "file $ROOTDIR/OBJ.linux.$(arch)/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args $ROOTDIR --config $conf --verbose --verbose >OUTPUT/transport-flat.conf-out" >>.gdbinit

eval ${OBJDIRTOP}/programs/readwriteconf/readwriteconf $ROOTDIR --config ${conf}


