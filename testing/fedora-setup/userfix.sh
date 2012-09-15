#!/bin/sh

MYGROUPID=`id -g`
MYGROUPNAME=`id -g -n`
if [ -z "`grep qemu /etc/group |grep $MYGROUPID`" ]
then
	echo "The qemu user needs write access in your swan tree"
	echo "Add the qemu user to your group using: sudo usermod -a -G $MYGROUPNAME qemu"
	echo "Ensure that the libreswan tree is group writable"
	echo "(or worse, world writable)"
	echo "You might also need to set SElinux in permissive mode for now"
fi


