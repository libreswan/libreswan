ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-default
../../guestbin/ipsec-kernel-state.sh | grep 'replay[-_=]'
ipsec stop

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-0
../../guestbin/ipsec-kernel-state.sh | grep 'replay[-_=]'
ipsec stop

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-64
../../guestbin/ipsec-kernel-state.sh | grep 'replay[-_=]'
ipsec stop

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-256
../../guestbin/ipsec-kernel-state.sh | grep 'replay[-_=]'
ipsec stop

echo done
