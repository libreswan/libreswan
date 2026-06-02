/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started

netcap --json --advanced | jq --monochrome-output '.planes[]?.ifaces[]?.addrs[]?.endpoints[]? | if .processes[]?.comm == "pluto" then pick(.label, .processes[]?.caps) else empty end'
