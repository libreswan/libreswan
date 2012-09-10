#!/bin/bash

if [ ! -f ../../Makefile.inc ]; then
       echo "Please run this from testing/fedora-setup/ as cwd until this becomes a Makefile"
       exit 1
fi

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
    --extra-args="swanname=base ks=file:/swanbase.ks \
      console=tty0 console=ttyS0,115200" \
    --name=swanbase \
    --disk $BASE/swanbase.img,size=8 \
    --ram 1024 \
    --vcpus=1 \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$tree  \
    --nographics 
fi

for hostname in east west;
do
	sudo cp $BASE/swanbase.img  $BASE/$hostname.img
done
