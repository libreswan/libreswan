#!/bin/sh

#  
#
#

TMP=/mara6/space/tmp export TMP
export KLIPS_DEBUG=true

BUILDTOP=${MYBOX-/c2/freeswan/freeswan-1.92}
export BUILDTOP
. $BUILDTOP/umlsetup.sh

me=`basename $0`
meup=`echo $me | tr a-z A-Z`

MYDIR=$POOLSPACE/$me

horz=+400
vert=+10
columns=80
rows=40
case $me in
	sunset)  horz=+0;  vert=+10; rows=24;;

	west)    horz=+0;  vert=-0;;

	east)    horz=-0;vert=-0 ;;
        north)   horz=+30; vert=+0;;

	sunrise) horz=+384;vert=+10; rows=24;;

	nic)     horz=+0;  vert=+400; rows=18;;
	japan)   horz=+384;vert=+400;;	
	carrot)  horz=+400;vert=+20; rows=18;;
	beet)    horz=+400;vert=+200; rows=18;;
esac

rxvt -n $meup -T $meup -geometry ${columns}x${rows}${horz}${vert} -name $meup -e $MYDIR/start.sh $@ &
