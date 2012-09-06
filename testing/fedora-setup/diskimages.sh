#!/bin/bash

# Note: Replace this with your local Fedora tree if you have one.
#export tree=http://mirror.fedoraproject.org/linux/releases/17/Fedora/x86_64/os/
export tree=http://fedora.mirror.nexicom.net/linux/releases/17/Fedora/x86_64/os/
export BASE=/var/lib/libvirt/images/

if [ ! -f $BASE/swanbase.img ]
then
	echo "Creating swanbase image using libvirt"
# install base guest to obtain a file image that will be used as uml root
sudo virt-install --connect=qemu:///system \
    --network=bridge:virbr0,model=virtio \
    --initrd-inject=./swanbase.ks \
    --extra-args="swanname=base ks=file:/swanbase.ks \
      console=tty0 console=ttyS0,115200" \
    --name=swanbase \
    --disk $BASE/swanbase.img,size=8 \
    --ram 512 \
    --vcpus=1 \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$tree \
    --nographics 
fi

if [ ! -f $BASE/localswan.fs ]; then
	sudo dd if=/dev/zero of=$BASE/localswan.fs bs=1024k count=1024
	sudo mkfs.ext2 -F $BASE/localswan.fs
fi

if [ ! -f $BASE/swan.fs ]; then
	sudo dd if=/dev/zero of=$BASE/testingswan.fs bs=1024k count=1024
	sudo mkfs.ext2 -F $BASE/testingswan.fs
fi

if [ ! -d $BASE/tmp ]; then
	sudo mkdir $BASE/tmp
fi

if [ ! -f ../../Makefile.inc ]; then
	echo "Please run this from testing/fedora-setup/ as cwd"
	exit 1
fi

echo -n "Creating /testing image..."
sudo mount -o loop,rw $BASE/testingswan.fs $BASE/tmp
sudo cp -a ../../testing/* $BASE/tmp/
sudo umount $BASE/tmp/
echo "done"

echo -n "Creating /usr/local image..."
sudo mount -o loop,rw $BASE/localswan.fs $BASE/tmp
sudo cp -a /usr/local/* $BASE/tmp/
sudo umount $BASE/tmp/
echo "done"

