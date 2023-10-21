../../guestbin/wait-for.sh --match '^".*#2: IPsec SA established' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match '^".*#3: IPsec SA established' -- cat /tmp/pluto.log
