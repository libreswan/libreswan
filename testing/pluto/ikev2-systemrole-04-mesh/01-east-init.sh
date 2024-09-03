/testing/guestbin/swan-prep --nokeys
# System Role deployment on nic will push configurations to our machine
# into /etc/ipsec.d/
# because it will change files, we can't mount bind them. So use a fressh empty dir
rm -rf OUTPUT/east/ipsec.d
mkdir -p OUTPUT/east/ipsec.d/policies
chmod 777 OUTPUT/east
mount -o bind,rw OUTPUT/east/ipsec.d /etc/ipsec.d
( cd /etc/ipsec.d/policies; touch private private-or-clear clear block )
# initnss normally happens in the initsystem - but not for namespace testing
# ../../guestbin/if-namespace.sh ipsec initnss
ipsec initnss
ipsec pk12util -i /testing/x509/pkcs12/mainca/east.p12 -w /testing/x509/nss-pw
# test config for syntax errors
ipsec addconn --checkconfig --config /etc/ipsec.conf
# start for test
ipsec start
../../guestbin/wait-until-pluto-started
# test secrets reading for early warning of syntax errors
ipsec secrets
../../guestbin/if-namespace.sh /usr/sbin/sshd -o PidFile=/var/run/pluto/sshd.pid
# ready for System Role to drop file(s) into /etc/ipsec.d/
echo "initdone"
