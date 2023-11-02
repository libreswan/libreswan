# match iptables.sh

/^ iptables / b match-iptables
b end-iptables

# delete current line; advance to next
:next-iptables
  N
  s/^.*\n//
  /^[a-z]* #/ b end-iptables
  b subst-iptables

# normal
:match-iptables
  # print and read next line
  n
  /^[a-z]* #/ b end-iptables
  b subst-iptables

:subst-iptables

  # put back meaningful names lost by f38
  s/^\([A-Z][A-Z]* *\) 0   \( *\)/\1 all \2/
  s/^\([A-Z][A-Z]* *\) 6   \( *\)/\1 tcp \2/
  s/^\([A-Z][A-Z]* *\) 50  \( *\)/\1 esp \2/
  s/^\([A-Z][A-Z]* *\) 17  \( *\)/\1 udp \2/

b match-iptables

:end-iptables
