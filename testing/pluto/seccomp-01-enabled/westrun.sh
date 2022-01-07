ipsec auto --up nss-cert
ipsec auto --down nss-cert
# pluto should still be running
pidof pluto > /dev/null || echo not running?
# whack socket will hang because pluto is expected to die
ipsec whack --seccomp-crashtest & disown ; sleep 2
# pluto should not be running anymore
pidof pluto
# one entry of SECCOMP activating should show up in the log
ausearch -r -m seccomp -ts boot | sed "s/ip=.*/ip=XXX/"
# don't leave post-mortem.sh thinking pluto is running
rm /run/pluto/pluto.ctl
