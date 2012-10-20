#!/bin/bash

TESTING=`readlink -f $0  | sed "s/libvirt.*$/libvirt/"`
pushd $TESTING

echo "creating disks"

# Note: Replace this with your local Fedora tree if you have one.
export tree=http://fedora.mirror.nexicom.net/linux/releases/17/Fedora/x86_64/os/
#export tree=http://76.10.157.69/linux/releases/17/Fedora/x86_64/os
#export tree=http://192.168.157.69/linux/releases/17/Fedora/x86_64/os
export BASE=/var/lib/libvirt/images/

if [ ! -f $BASE/swanfedorabase.img ]
then
	echo "Creating swanfedorabase image using libvirt"

# check for hardware VM instructions
cpu="--hvm"
grep vmx /proc/cpuinfo > /dev/null || cpu=""

# Looks like newer virt-install requires the disk image to exist?? How odd
echo -n "creating 8 gig disk image...."
dd if=/dev/zero of=$BASE/swanfedorabase.img bs=1024k count=8192
echo done

# install base guest to obtain a file image that will be used as uml root
# For static networking add kernel args parameters ip=.... etc
# (network settings in kickstart are ignored by modern dracut)
sudo virt-install --connect=qemu:///system \
    --network=network:default,model=virtio \
    --initrd-inject=./fedorabase.ks \
    --extra-args="swanname=swanfedorabase ks=file:/fedorabase.ks \
      console=tty0 console=ttyS0,115200" \
    --name=swanfedorabase \
    --disk $BASE/swanfedorabase.img,size=8 \
    --ram 1024 \
    --vcpus=1 \
    --check-cpu \
    --accelerate \
    --location=$tree \
    --nographics \
    --autostart \
    --noreboot \
    $cpu
fi

# create many copies of this image using copy-on-write
sudo qemu-img convert -O qcow2 $BASE/swanfedorabase.img $BASE/swanfedorabase.qcow2
sudo chown qemu.qemu $BASE/swanfedorabase.qcow2

for hostname in east west north road;
do
	sudo qemu-img create -F qcow2 -f qcow2 -b $BASE/swanfedorabase.qcow2 $BASE/$hostname.qcow2
	sudo chown qemu.qemu $BASE/$hostname.qcow2
	if [ -f /usr/sbin/restorecon ] 
	then
		sudo restorecon $BASE/$hostname.qcow2
	fi
done

sudo virsh undefine swanfedorabase

popd

