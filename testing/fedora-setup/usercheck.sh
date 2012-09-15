#!/bin/sh

MYGROUPID=`id -g`
MYGROUPNAME=`id -g -n`
MYNAME=`id -nu`
if [ -z "`grep qemu /etc/group |grep $MYGROUPID`" ]
then
	echo "The qemu user needs write access in your swan tree"
	echo "Add the qemu user to your group using: sudo usermod -a -G $MYGROUPNAME qemu"
fi
if [ -z "`grep $MYNAME /etc/group |grep ^qemu`" ]
then
	echo "Your need write access for group qemu incase you create files in the VM"
	echo "Add yourself to the qemu group using: sudo usermod -a -G qemu $MYNAME"
fi

echo "Ensure that the libreswan tree is group writable (looking into fixing this)"
echo "(or worse, world writable)"
echo "You might also need to set SElinux in permissive mode for now"
