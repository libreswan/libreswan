#!/bin/bash

TESTING=`readlink -f $0  | sed "s/libvirt.*$/libvirt/"`
LIBRESWANSRC=`readlink -f $0  | sed "s/libreswan.*$/libreswan/"`

source $LIBRESWANSRC/kvmsetup.sh

echo "TESTING=$TESTING"
echo "LIBRESWANSRC=$LIBRESWANSRC"
echo "POOLSPACE=$POOLSPACE"
echo "OSTYPE=$OSTYPE"
echo "OSMEDIA=$OSMEDIA"

if [ -z "$POOLSPACE" -o -z "$OSTYPE" -o -z "$OSMEDIA" ]
then
	echo "broken kvmsetup.sh, aborted"
	exit 42
fi

touch /var/lib/libvirt/qemu/lswantest || (
	echo "The qemu group needs write permissions in /var/lib/libvirt/qemu/"
	exit 43
)
rm -f /var/lib/libvirt/qemu/lswantest

if [ ! -d "$POOLSPACE" ]
then
	mkdir -p $POOLSPACE 
	chmod a+x $POOLSPACE
fi

# Let's start
pushd $TESTING

echo "testing "$OSTYPE"base.ks"

if [ ! -f "$OSTYPE"base.ks ]
then
	echo "unknown distribution, no kickstart file found"
	exit 42
fi

echo "creating VM disk images"

if [ ! -f $POOLSPACE/swan"$OSTYPE"base.img ]
then
	echo "Creating base $OSTYPE image using libvirt"

	# check for hardware VM instructions
	cpu="--hvm"
	grep vmx /proc/cpuinfo > /dev/null || cpu=""

	# install base guest to obtain a file image that will be used as uml root
	# For static networking add kernel args parameters ip=.... etc
	# (network settings in kickstart are ignored by modern dracut)
	sudo virt-install --connect=qemu:///system \
	   --network=network:default,model=virtio \
	   --initrd-inject=./"$OSTYPE"base.ks \
	   --extra-args="swanname=swan"$OSTYPE"base ks=file:/'$OSTYPE'base.ks \
	   console=tty0 console=ttyS0,115200" \
	   --name=swan"$OSTYPE"base \
	   --disk $POOLSPACE/swan"$OSTYPE"base.img,size=8 \
	   --ram 1024 \
	   --vcpus=1 \
	   --check-cpu \
	   --accelerate \
	   --location=$OSMEDIA \
	   --nographics \
	   --autostart \
	   --noreboot \
	   $cpu
fi

# Create the virtual networks

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


# create many copies of this image using copy-on-write
qemu-img convert -O qcow2 $POOLSPACE/swan"$OSTYPE"base.img $POOLSPACE/swan"$OSTYPE"base.qcow2

for hostname in $LIBRESWANHOSTS;
do
	qemu-img create -F qcow2 -f qcow2 -b $POOLSPACE/swan"$OSTYPE"base.qcow2 $POOLSPACE/$hostname.qcow2
	if [ -f /usr/sbin/restorecon ] 
	then
		sudo restorecon $POOLSPACE/$hostname.qcow2
	fi
done
sudo virsh undefine swan"$OSTYPE"base

# Use the the base disk to create VM disks
for hostname in $LIBRESWANHOSTS;
do
	rm -f vm/$hostname.xml.converted 
	cp vm/$hostname.xml vm/$hostname.xml.converted
	sed -i "s:@@TESTING@@:$TESTING:" vm/$hostname.xml.converted
	sed -i "s:@@LIBRESWANSRCDIR@@:$LIBRESWANSRCDIR:" vm/$hostname.xml.converted
	sed -i "s:@@POOLSPACE@@:$POOLSPACE:" vm/$hostname.xml.converted
        sudo virsh define vm/$hostname.xml.converted
	rm -f vm/$hostname.xml.converted 
        sudo virsh start $hostname
done

popd

echo "done"

