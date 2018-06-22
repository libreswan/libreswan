ipsec auto --up nss-cert
ipsec auto --down nss-cert
# pluto should still be running
pidof pluto > /dev/null || echo not running?
# whack socket will hang because pluto is expected to die
ipsec whack --seccomp-crashtest --asynchronous &
disown
sleep 1
# pluto should not be running anymore
pidof pluto
# one entry of SECCOMP activating should show up in the log
grep SECCOMP /var/log/audit/audit.log | sed "s/ip=.*/ip=XXX/"
echo done
