../../guestbin/prep.sh

left=192.1.2.45
right=192.1.2.23
leftsubnet=192.0.1.0/24
rightsubnet=192.0.2.0/24

../../guestbin/start-racoon.sh

# create a partial state on east, don't hold the hack for retransmit
racoonctl establish-sa -w isakmp inet ${left} ${right}

echo "spdadd ${leftsubnet}[any] ${rightsubnet}[any] any -P out ipsec esp/tunnel/${left}-${right}/require;" | setkey -c
echo "spdadd ${rightsubnet}[any] ${leftsubnet}[any] any -P in  ipsec esp/tunnel/${right}-${left}/require;" | setkey -c

# can't use -w as it is fakey, see NetBSD 59347
racoonctl establish-sa esp inet ${leftsubnet}/255 ${rightsubnet}/255 any
# so instead wait for the SAs to appear
../../guestbin/wait-for.sh --match "${left} ${right}" -- ipsec _kernel state
../../guestbin/wait-for.sh --match "${right} ${left}" -- ipsec _kernel state

ipsec _kernel state
ipsec _kernel policy

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
