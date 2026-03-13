# match: ipsec restart

/^ ipsec restart/,/^[a-z][a-z]* #$/ {

  # FreeBSD: Waiting for PIDS: 1192.
  /Waiting for PIDS: / s/[0-9][0-9]*/PID/

  # always present
  s/Redirecting to:.*$/Redirecting to: [initsystem]/

  # Namespaces: from underlaying whack command
  /Pluto is shutting down/ d
}
