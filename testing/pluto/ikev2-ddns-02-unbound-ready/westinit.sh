/testing/guestbin/swan-prep --nokeys

# need to disable ipv6 and activate auto-interface
cp resolv.conf /etc
cp west-unbound.conf /etc/unbound/unbound.conf
unbound-control-setup > /dev/null 2>&1
# use modified service file that skips ICANN root key checks
cat /lib/systemd/system/unbound.service | grep -v ExecStartPre > /etc/systemd/system/unbound.service
systemctl daemon-reload
systemctl start unbound.service
unbound-control local_data right.libreswan.org 3600 IN A 192.1.2.23
dig +short right.libreswan.org @127.0.0.1
dig +dnssec +short right.libreswan.org @127.0.0.1

ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
