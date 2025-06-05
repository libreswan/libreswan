../../guestbin/swan-prep --nokeys

../../guestbin/ifconfig.sh eth0 add 192.0.20.254/24

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add any-east
ipsec whack --impair suppress_retransmits
echo initdone
