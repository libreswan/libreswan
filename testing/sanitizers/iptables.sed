# match iptables.sh

/^ iptables /,/^[a-z][a-z]* #$/ {

  # put back meaningful names lost by f38
  s/^\([A-Z][A-Z]* *\) 0   \( *\)/\1 all \2/
  s/^\([A-Z][A-Z]* *\) 6   \( *\)/\1 tcp \2/
  s/^\([A-Z][A-Z]* *\) 50  \( *\)/\1 esp \2/
  s/^\([A-Z][A-Z]* *\) 17  \( *\)/\1 udp \2/

}
