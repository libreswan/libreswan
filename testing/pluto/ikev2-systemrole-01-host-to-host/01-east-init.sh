/testing/guestbin/swan-prep --nokeys
# System Role deployment on nic will push configurations to our machine
# into /etc/ipsec.d/
rm -rf OUTPUT/east/ipsec.d
mkdir -p OUTPUT/east/ipsec.d
chmod 777 OUTPUT/east
mount -o bind,rw OUTPUT/east/ipsec.d /etc/ipsec.d
# test config for syntax errors
ipsec addconn --checkconfig --config /etc/ipsec.conf
# start for test
ipsec start
../../guestbin/wait-until-pluto-started
# test secrets reading for early warning of syntax errors
ipsec secrets
/testing/guestbin/sshd.sh start
# ready for System Role to drop file(s) into /etc/ipsec.d/
echo "initdone"
