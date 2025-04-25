# match: ipsec start

/^ ipsec start/,/^[a-z][a-z]* #$/ {

  s/Redirecting to:.*$/Redirecting to: [initsystem]/

}
