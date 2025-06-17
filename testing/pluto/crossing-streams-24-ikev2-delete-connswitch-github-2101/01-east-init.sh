/testing/guestbin/swan-prep --nokey

../../guestbin/ifconfig.sh eth0 add 192.0.20.254/24

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits

ipsec add a
ipsec add b
