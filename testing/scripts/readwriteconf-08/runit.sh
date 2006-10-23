#!/bin/sh

# assumes that 
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

exe=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
args="--config ipsec.conf"
echo "file $exe" >.gdbinit
echo "set args $args " >>.gdbinit

eval $exe $args 

