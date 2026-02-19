/testing/guestbin/swan-prep --nokeys
cp ../../guestbin/updown.sh /tmp
chmod a+x /tmp/updown.sh

show_dns_resolver() { printf "ipsec status: " ; ipsec status | sed -n -e 's/.* \(dns-resolver=[^, ]*\).*/\1/p' ; printf "updown: " ; grep PLUTO_DNS_RESOLVER /tmp/updown.env ; }

cp west.conf /etc/ipsec.conf
ipsec start
../../guestbin/wait-until-pluto-started
show_dns_resolver
ipsec stop

cp west-dns-resolver-systemd.conf /etc/ipsec.conf
ipsec start
../../guestbin/wait-until-pluto-started
show_dns_resolver
ipsec stop
