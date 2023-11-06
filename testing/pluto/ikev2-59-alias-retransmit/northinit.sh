/testing/guestbin/swan-prep
rm -fr /var/run/pluto/pluto.pid
ipsec pluto --impair helper_thread_delay:2 --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add north-eastnets
echo "initdone"
