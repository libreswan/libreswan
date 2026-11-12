ipsec whack --impair revival
ipsec up westnet-eastnet-ipcomp
../../guestbin/wait-for-pluto.sh --match '#1: Child SA #2 no longer exists, ignoring delete response'
