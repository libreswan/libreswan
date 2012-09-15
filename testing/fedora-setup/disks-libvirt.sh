#!/bin/bash

TESTING=`readlink -f $0  | sed "s/fedora-setup.*$/fedora-setup/"`
pushd $TESTING

echo "creating disks"

# Note: Replace this with your local Fedora tree if you have one.
#export tree=http://mirror.fedoraproject.org/linux/releases/17/Fedora/x86_64/os/
#export tree=http://fedora.mirror.nexicom.net/linux/releases/17/Fedora/x86_64/os/
export tree=http://76.10.157.69/linux/releases/17/Fedora/x86_64/os
#export tree=http://192.168.157.69/linux/releases/17/Fedora/x86_64/os
export BASE=/var/lib/libvirt/images/

if [ ! -f $BASE/swanbase.img ]
then
	echo "Creating swanbase image using libvirt"
# install base guest to obtain a file image that will be used as uml root
sudo virt-install --connect=qemu:///system \
    --network=network:default,model=virtio \
    --initrd-inject=./swanbase.ks \
    --extra-args="swanname=swanbase ks=file:/swanbase.ks \
      console=tty0 console=ttyS0,115200" \
    --name=swanbase \
    --disk $BASE/swanbase.img,size=8 \
    --ram 1024 \
    --vcpus=1 \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$tree  \
    --nographics \
    --autostart  \
    --noreboot
fi

# create many copies of this image using copy-on-write
sudo qemu-img convert -O qcow2 $BASE/swanbase.img $BASE/swanbase.qcow2
sudo chown qemu.qemu $BASE/swanbase.qcow2

for hostname in east west north road;
do
	sudo qemu-img create -F qcow2 -f qcow2 -b $BASE/swanbase.qcow2 $BASE/$hostname.qcow2
	sudo chown qemu.qemu $BASE/$hostname.qcow2
	if [ -f /usr/sbin/restorecon ] 
	then
		sudo restorecon $BASE/$hostname.qcow2
	fi
done

sudo virsh undefine swanbase

popd

