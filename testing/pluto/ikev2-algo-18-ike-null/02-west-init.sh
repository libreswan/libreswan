../../guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair allow-null-none
ipsec add algo
