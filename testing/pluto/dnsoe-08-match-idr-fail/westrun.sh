ipsec up --asynchronous west-east
../../guestbin/wait-for.sh --match '#1: fetching IDr IPsec key using DNS failed' -- grep -s 'fetching IDr' /tmp/pluto.log
# again, this time west has the DNS answers cached
ipsec up --asynchronous west-east
../../guestbin/wait-for.sh --match '#3: fetching IDr IPsec key using DNS failed' -- grep -s 'fetching IDr' /tmp/pluto.log
echo done
