/testing/guestbin/swan-prep --nokeys
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ipv4-psk-ppk
ipsec connectionstatus westnet-eastnet-ipv4-psk-ppk
echo "initdone"
