#!/bin/bash

# if using libvirt, you can use network-libvirt.sh instead

sudo ip tuntap add dev swan01-nic mode tap #user build group build
sudo ip link set dev swan01-nic address 12:00:00:16:16:BA
sudo brctl addbr swan01
sudo brctl addif swan01 swann01-nic
sudo ip link set dev swan01-nic up
sudo ip addr add 192.0.1.127/24 dev swan01 
sudo ip set swan01 up

sudo ip tuntap add dev swan02-nic mode tap #user build group build
sudo ip link set dev swan02-nic address 12:00:00:32:32:BA
sudo brctl addbr swan02
sudo brctl addif swan02 swann02-nic
sudo ip link set dev swan02-nic up
sudo ip addr add 192.0.2.127/24 dev swan02 
sudo ip set swan02 up

sudo ip tuntap add dev swan10-nic mode tap #user build group build
sudo ip link set dev swan10-nic address 12:00:00:DE:AD:BA
sudo brctl addbr swan10
sudo brctl addif swan10 swann10-nic
sudo ip link set dev swan10-nic up
sudo ip addr add 192.1.2.254/24 dev swan10 
sudo ip set swan10 up

sudo ip tuntap add dev swan13-nic mode tap #user build group build
sudo ip link set dev swan13-nic address 12:00:00:32:64:BA
sudo brctl addbr swan13
sudo brctl addif swan13 swann10-nic
sudo ip link set dev swan13-nic up
sudo ip addr add 192.1.3.254/24 dev swan13 
sudo ip set swan13 up

sudo ip tuntap add dev swan14-nic mode tap #user build group build
sudo ip link set dev swan14-nic address 12:00:00:16:32:BA
sudo brctl addbr swan14
sudo brctl addif swan14 swann10-nic
sudo ip link set dev swan14-nic up
sudo ip addr add 192.1.4.254/24 dev swan14 
sudo ip set swan14 up

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


