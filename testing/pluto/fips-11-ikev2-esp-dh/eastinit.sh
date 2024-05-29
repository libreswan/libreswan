/testing/guestbin/swan-prep
ip addr add 192.0.200.254/24 dev eth0:1
../../guestbin/route.sh add 192.0.100.0/24 via 192.1.2.45  dev eth1
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh ikev2-esp=aes-sha1-modp4096 ikev2-base
echo "initdone"
