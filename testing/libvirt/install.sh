#!/bin/bash

TESTING=`readlink -f $0  | sed "s/libvirt.*$/libvirt/"`
TESTDIR=`readlink -f $0  | sed "s/libvirt.*$//"`
LIBRESWANSRCDIR=`readlink -f $0  | sed "s/libreswan.*$/libreswan/"`

source $LIBRESWANSRCDIR/kvmsetup.sh

echo "TESTDIR=$TESTDIR"
echo "LIBRESWANSRCDIR=$LIBRESWANSRCDIR"
echo "POOLSPACE=$POOLSPACE"
echo "OSTYPE=$OSTYPE"
echo "OSMEDIA=$OSMEDIA"

# if we don't have certificates yet, generate them
if [ ! -f  $LIBRESWANSRCDIR/testing/x509/pkcs12/mainca/west.p12 ]
then
	pushd $LIBRESWANSRCDIR/testing/x509
	./dist_certs
	popd
fi

if [ -z "$POOLSPACE" -o -z "$OSTYPE" -o -z "$OSMEDIA" -o -z "$LIBRESWANSRCDIR" ]
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

for netname in net/*
do
  net=`basename $netname`
  if [ -z "`sudo virsh net-list --all |grep $net | awk '{ print $1}'`" ];
  then
	sudo virsh net-define net/$net
	echo $net created 
	sudo virsh net-start $net
	echo $net activated
  elif [ -n "`sudo virsh net-list --all |grep inactive |grep $net | awk '{ print $1}'`" ];
	then
		sudo virsh net-start $net
		echo $net activated
  else
	echo $net already exists - not created
  fi
done

# create many copies of this image using copy-on-write
qemu-img convert -O qcow2 $POOLSPACE/swan"$OSTYPE"base.img $POOLSPACE/swan"$OSTYPE"base.qcow2

for hostfilename in vm/*
do
  hostname=`basename $hostfilename`
	# Use the the base disk to create VM disks
	qemu-img create -F qcow2 -f qcow2 -b $POOLSPACE/swan"$OSTYPE"base.qcow2 $POOLSPACE/$hostname.qcow2
	if [ -f /usr/sbin/restorecon ] 
	then
		sudo restorecon $POOLSPACE/$hostname.qcow2
	fi

	# Create VM
	rm -f vm/$hostname.converted 
	cp vm/$hostname vm/$hostname.converted
	sed -i "s:@@TESTDIR@@:$TESTDIR:" vm/$hostname.converted
	sed -i "s:@@LIBRESWANSRCDIR@@:$LIBRESWANSRCDIR:" vm/$hostname.converted
	sed -i "s:@@POOLSPACE@@:$POOLSPACE:" vm/$hostname.converted
	sed -i "s:@@USER@@:`id -u`:" vm/$hostname.converted
	sed -i "s:@@GROUP@@:`id -g qemu`:" vm/$hostname.converted
        sudo virsh define vm/$hostname.converted
	rm -f vm/$hostname.converted 
        sudo virsh start $hostname
done

sudo virsh undefine swan"$OSTYPE"base
popd

echo "done"

