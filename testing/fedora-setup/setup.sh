#!/bin/bash

# Note: Replace this with your local Fedora tree if you have one.
tree=http://fedora.mirror.nexicom.net/linux/releases/17/Fedora/x86_64/os/
#tree=http://mirror.fedoraproject.org/linux/releases/17/Fedora/x86_64/os/


for net in net/swan*
do
  if [ ! -d /sys/class/$net ];
  then
     virsh net-create $net
     echo $net created and activated
  else
     echo $net already exists - not created
  fi
done

# we need to be "nic", so we need some host routes
sudo ip route add -net 192.0.1.0 netmask 255.255.255.0 gw 192.1.2.45
sudo ip route add -net 192.0.2.0 netmask 255.255.255.0 gw 192.1.2.23
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



# install base guest to obtain a file image that will be used as uml root
virt-install --connect=qemu:///system \
    --network=bridge:virbr0,model=virtio \
    --initrd-inject=./swanbase.ks \
    --extra-args="swanname=base ks=file:/swanbase.ks \
      console=tty0 console=ttyS0,115200" \
    --name=swanbase \
    --disk /var/lib/libvirt/images/swanbase.img,size=8 \
    --ram 512 \
    --vcpus=1 \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$tree \
    --nographics 

echo Creating Copy-On-Write files for images
# use base image for individual Copy-On-Write guests (west, east, etc)
#$BASE=/var/lib/libvirtd/images/
#qemu-img create -f qcow2 -b $BASE/swanbase.img $BASE/swanwest.img
#qemu-img create -f qcow2 -b $BASE/swanbase.img $BASE/swaneast.img


