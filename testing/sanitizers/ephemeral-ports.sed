# fix up output containing random numbers

s/ 192.1.2.\([0-9]*\):[0-9]* STATE_/ 192.1.2.\1:XXXXX STATE_/
s/ 192.1.2.\([0-9]*\):[0-9]*: message ignored/ 192.1.2.\1:XXXXX message ignored/
s/ 192.1.2.\([0-9]*\):[0-9]*: sending notification/ 192.1.2.\1:XXXXX sending notification/

# match: ip (|-[46]) xfrm state ...
/^ ip xfrm state/ b match
/^ ip -4 xfrm state/ b match
/^ ip -6 xfrm state/ b match

# match: ipsec look et.al.
/^ ipsec look/ b match
/^ .*ipsec-look.sh/ b match

b end

:match

  # print and read next line
  n
  /^[a-z]* #/ b end

  # ephemeral ports
  # - according to IANA: 49152-65535
  # - according to Linux: 32768-61000
  # the below matches 30000-..  which is good enough
  # but not good enough because fedora23 starts in the 29xxx range now :P
  s/ sport [2-6][0-9][0-9][0-9][0-9] / sport EPHEMERAL /g
  s/ dport [2-6][0-9][0-9][0-9][0-9] / dport EPHEMERAL /g;

b match

:end
