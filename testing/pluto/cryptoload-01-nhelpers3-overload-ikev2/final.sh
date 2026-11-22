# both east and west should have 37 tunnels
../../guestbin/wait-for.sh --timeout 180 --match ', active 37' -- ipsec status

ipsec _kernel state --sort
ipsec _kernel policy
ipsec stop
