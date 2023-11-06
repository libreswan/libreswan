/testing/guestbin/swan-prep
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/pluto --impair helper_thread_delay:1 --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
echo "initdone"
