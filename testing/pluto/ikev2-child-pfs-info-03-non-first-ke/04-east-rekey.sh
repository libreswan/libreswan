# east initiates the Child SA rekey; it must settle on DH20, not DH19
ipsec whack --rekey-child --name west-east
../../guestbin/wait-for-pluto.sh '#3: initiator rekeyed Child SA #2'
ipsec whack --trafficstatus
