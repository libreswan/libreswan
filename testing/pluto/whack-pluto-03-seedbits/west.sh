/testing/guestbin/swan-prep --nokeys

sed "s/seedbits=.*$/seedbits=520/" ipsec.conf > /etc/ipsec.conf
ipsec start
../../guestbin/wait-until-pluto-started
ipsec stop
grep -E "^seeded" /tmp/pluto.log

sed "s/seedbits=.*$/seedbits=1024/" ipsec.conf > /etc/ipsec.conf
ipsec start
../../guestbin/wait-until-pluto-started
ipsec stop
grep -E "^seeded" /tmp/pluto.log

sed "s/seedbits=.*$/seedbits=2048/" ipsec.conf > /etc/ipsec.conf
ipsec start
../../guestbin/wait-until-pluto-started
ipsec stop
grep -E "^seeded" /tmp/pluto.log

ipsec pluto --config /etc/ipsec.conf --seedbits=1024
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown
grep -E "^seeded" /tmp/pluto.log

# Test with custom seeddev
ipsec pluto --config /etc/ipsec.conf --leak-detective --seedbits=520 --seeddev /dev/urandom
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown
grep -E "^seeded" /tmp/pluto.log
