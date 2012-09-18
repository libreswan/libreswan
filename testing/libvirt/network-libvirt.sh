#!/bin/bash

TESTING=`readlink -f $0  | sed "s/libvirt.*$/libvirt/"`
pushd $TESTING

for netname in net/swan*
do
  net=`echo $netname|sed "s/^net\///g"`
  if [ ! -d /sys/class/$net ];
  then
	sudo virsh net-define net/$net
	echo $net created 
  else
	echo $net already exists - not created
  fi
done

for net in `sudo virsh net-list --inactive| sed "s/^\(192.*\) *inactive.*$/\1/" |grep 192`
do
	sudo virsh net-start $net
	echo $net activated
done
popd
