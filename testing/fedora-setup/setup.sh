#!/bin/bash

# Note: Replace this with your local Fedora tree if you have one.
#export tree=http://mirror.fedoraproject.org/linux/releases/17/Fedora/x86_64/os/
export tree=http://fedora.mirror.nexicom.net/linux/releases/17/Fedora/x86_64/os/
export BASE=/var/lib/libvirt/images/

for net in net/swan*
do
  if [ ! -d /sys/class/$net ];
  then
     sudo virsh net-create $net
     echo $net created and activated
  else
     echo $net already exists - not created
  fi
done

# we need to be "nic", so we need some host routes
sudo ip route add 192.0.1.0/24 via 192.1.2.45
sudo ip route add 192.0.2.0/24 via  192.1.2.23
sudo ip -6 addr add 2001:db8:1:2::254/64 dev swan12
sudo ip addr add 192.1.2.129 dev swan12
sudo ip addr add 192.1.2.130 dev swan12
# okay, now add interfaces for when we are the default route for pieces
# of the reverse name.
sudo ip addr add 192.1.2.62 dev swan12
sudo ip addr add 192.1.2.30 dev swan12

#sudo ip addr add 192.1.3.254 dev swan13
#sudo ip -6 addr add 2001:db8:1:3::254/64 dev swan13
#sudo ip addr add 192.1.4.254 dev swan14

# unused
#sudo ip addr add 192.9.4.254 dev swan94
#sudo ip -6 addr add 2001:db8:9:4::254/64 dev swan94


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

