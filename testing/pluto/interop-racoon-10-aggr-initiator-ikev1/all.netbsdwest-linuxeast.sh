east# /testing/guestbin/prep.sh
east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add west-east
east# ipsec whack --impair revival
east# echo "initdone"

west# ../../guestbin/prep.sh

west# left=192.1.2.45
west# right=192.1.2.23
west# leftsubnet=192.0.1.0/24
west# rightsubnet=192.0.2.0/24

west# ../../guestbin/start-racoon.sh

# create a partial state on east, don't hold the hack for retransmit

west# racoonctl establish-sa -w isakmp inet ${left} ${right}

west# echo "spdadd ${leftsubnet}[any] ${rightsubnet}[any] any -P out ipsec esp/tunnel/${left}-${right}/require;" | setkey -c
west# echo "spdadd ${rightsubnet}[any] ${leftsubnet}[any] any -P in  ipsec esp/tunnel/${right}-${left}/require;" | setkey -c

# can't use -w as it is fakey, see NetBSD 59347

west# racoonctl establish-sa esp inet ${leftsubnet}/255 ${rightsubnet}/255 any

# so instead wait for the SAs to appear

west# ../../guestbin/wait-for.sh --match "${left} ${right}" -- ipsec _kernel state
west# ../../guestbin/wait-for.sh --match "${right} ${left}" -- ipsec _kernel state

west# ipsec _kernel state
west# ipsec _kernel policy

west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
