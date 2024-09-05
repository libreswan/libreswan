../../guestbin/tcpdump.sh --stop -i eth1
../../guestbin/nic-nat.sh 192.1.3.0/24 192.1.2.254 50000 1
../../guestbin/tcpdump.sh --start -i eth1
