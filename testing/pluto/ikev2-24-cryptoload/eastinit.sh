/testing/guestbin/swan-prep
ipsec pluto --impair helper_thread_delay:10 --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add multi
echo "initdone"
