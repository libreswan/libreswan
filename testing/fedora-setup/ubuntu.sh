#!/bin/bash

TESTING=`readlink -f $0  | sed "s/fedora-setup.*$/fedora-setup/"`
pushd $TESTING

echo "creating disks"

# Note: Replace this with your local Fedora tree if you have one.
#export tree=http://mirror.fedoraproject.org/linux/releases/17/Fedora/x86_64/os/
#export tree=http://76.10.157.69/linux/releases/17/Fedora/x86_64/os
#export tree=http://76.10.157.69/ubuntu/dists/precise/main/installer-amd64/
export tree=http://ftp.ubuntu.com/ubuntu/dists/precise/main/installer-amd64/
export BASE=/var/lib/libvirt/images/

if [ ! -f $BASE/swanubuntubase.img ]
then
	echo "Creating swanubuntubase image using libvirt"
# install base guest to obtain a file image that will be used as uml root
sudo virt-install --connect=qemu:///system \
    --network=network:default,model=virtio \
    --initrd-inject=./swanubuntubase.ks \
    --extra-args="swanname=swanubuntubase ks=file:/swanubuntubase.ks \
      console=tty0 console=ttyS0,115200" \
    --name=swanubuntubase \
    --disk $BASE/swanubuntubase.img,size=8 \
    --ram 1024 \
    --vcpus=1 \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$tree  \
    --autostart  \
    --noreboot \
    --nographics \

fi

# create many copies of this image using copy-on-write
sudo qemu-img convert -O qcow2 $BASE/swanubuntubase.img $BASE/swanubuntubase.qcow2
sudo chown qemu.qemu $BASE/swanubuntubase.qcow2

for hostname in east west north road;
do
	sudo qemu-img create -F qcow2 -f qcow2 -b $BASE/swanubuntubase.qcow2 $BASE/$hostname.qcow2
	sudo chown qemu.qemu $BASE/$hostname.qcow2
	if [ -f /usr/sbin/restorecon ] 
	then
		sudo restorecon $BASE/$hostname.qcow2
	fi
done

sudo virsh undefine swanubuntubase

popd

