/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east
ipsec whack --impair revival
echo initdone
ipsec auto --up road-east | sed -e "s/192.0.2.10./192.0.2.10X/" | sort # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
echo done
