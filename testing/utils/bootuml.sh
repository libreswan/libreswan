#!/bin/sh
#
# configuration for this file has moved to $OPENSWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at
# umlsetup-sample.sh
# in this directory. Copy it to $OPENSWANSRCDIR and edit it.
#
OPENSWANSRCDIR=${OPENSWANSRCDIR-../..}
if [ ! -f ${OPENSWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in umlsetup-sample.sh.
    exit 1
fi
	
export OPENSWANSRCDIR
. $OPENSWANSRCDIR/umlsetup.sh

me=`basename $0`
meup=`echo $me | tr a-z A-Z`

MYDIR=$POOLSPACE/$me

horz=400
vert=10
case $me in
	sunset)  horz=30;  vert=380;;

	west)    horz=30;  vert=10;;

	east)    horz=530; vert=10;;

	sunrise) horz=530; vert=380;;	

	nic)     horz=530; vert=750;;

	japan)   horz=30;  vert=750;;	
esac

xterm +sb -n $meup -T $meup -geometry 80x25+$horz+$vert -name $meup -e $MYDIR/start.sh $@ &
#rxvt -n $meup -T $meup -geometry 80x40+$horz+$vert -name $meup -e $MYDIR/start.sh $@ &
