set# ../../guestbin/prep.sh
set# ipsec start
set# ../../guestbin/wait-until-pluto-started
set# ipsec whack --impair suppress_retransmits
set# ipsec add rise-set
set# echo "initdone"

rise# ../../guestbin/prep.sh
rise# ipsec start
rise# ../../guestbin/wait-until-pluto-started
rise# ipsec add rise-set
rise# echo "initdone"

rise# ipsec up rise-set
rise# ipsec _kernel state
rise# ipsec _kernel policy
rise# ../../guestbin/ping-once.sh --up 198.18.1.15
rise# ipsec down rise-set
rise# ipsec _kernel state
