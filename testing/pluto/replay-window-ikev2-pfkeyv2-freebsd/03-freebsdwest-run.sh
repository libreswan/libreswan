ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-default
ipsec _kernel state | grep 'replay[-_=]'
ipsec stop

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-0
ipsec _kernel state | grep 'replay[-_=]'
ipsec stop

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-64
ipsec _kernel state | grep 'replay[-_=]'
ipsec stop

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-256
ipsec _kernel state | grep 'replay[-_=]'
ipsec stop

echo done
