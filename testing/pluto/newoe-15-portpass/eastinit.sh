/testing/guestbin/swan-prep
(test -z $(ip netns identify) || /usr/sbin/sshd -p 22 > /dev/null 2>/dev/null &)
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
ipsec auto --add passthrough-in
ipsec auto --route passthrough-in
ipsec auto --add passthrough-out
ipsec auto --route passthrough-out
echo "initdone"
