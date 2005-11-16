#!/bin/sh

BUILDTOP=${MYBOX-/c2/freeswan/freeswan-1.92}
export BUILDTOP
OPENSWANSRCDIR=$BUILDTOP 
export OPENSWANSRCDIR

. $BUILDTOP/umlsetup.sh

unset UML_public_CTL
unset UML_west_CTL
unset UML_east_CTL

if [ -f testparams.sh ]
then
    source testparams.sh
fi

case $* in
	0) if [ -n "$XHOST_LIST" ]; then
		    hosts=`echo $XHOST_LIST | tr 'A-Z' 'a-z'`
	 fi;;
        *) hosts=$@;;
esac

eval expect -f $BUILDTOP/testing/utils/localswitches.tcl $hosts

