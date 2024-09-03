/testing/guestbin/swan-prep --nokeys
# we can't test the packetflow as we are going to redirect
../../guestbin/ip.sh route del 192.0.2.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
