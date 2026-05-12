/testing/guestbin/swan-prep
../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
echo "192.1.2.23 peer.libreswan.org" >> /etc/hosts
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

# the name still resolves to the same address; both conns are left alone
ipsec add --autoall

# point the name somewhere else; rewrite in place, /etc/hosts is bind mounted
grep -v peer.libreswan.org /etc/hosts > /tmp/hosts.next
echo "5.6.7.9 peer.libreswan.org" >> /tmp/hosts.next
cat /tmp/hosts.next > /etc/hosts

# only the conn using the name is rebuilt
ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u
