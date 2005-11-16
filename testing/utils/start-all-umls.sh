#!/bin/sh 
#
# configuration for this file has moved to $OPENSWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at
# umlsetup-sample.sh
# in this directory. Copy it to $OPENSWANSRCDIR and edit it.
#
cd `dirname $0`
OPENSWANSRCDIR=${OPENSWANSRCDIR-../..}
if [ ! -f ${OPENSWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in umlsetup-sample.sh.
    exit 1
fi
	
export OPENSWANSRCDIR
. $OPENSWANSRCDIR/umlsetup.sh

for i in $REGULARHOSTS $FREESWANHOSTS
do
	ln -sfn bootuml.sh $i
	sh $i
done
