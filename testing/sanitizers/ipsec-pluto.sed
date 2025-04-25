# match: ipsec start

/^ ipsec pluto/,/^[a-z][a-z] $/ {

  s/Redirecting to:.*$/Redirecting to: [initsystem]/

  s/^\(Starting Pluto (Libreswan Version\) .* pid:.*$/\1 ...) pid:PID/
  s/^\(operating system\): .*/\1: .../

}
