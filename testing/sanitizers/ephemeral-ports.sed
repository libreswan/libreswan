# fix up output containing random numbers

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
  / sport [3-6][0-9][0-9][0-9][0-9] / {
    s/ sport [0-9]\+ / sport EPHEMERAL /g;
  }
  / dport [3-6][0-9][0-9][0-9][0-9] / {
    s/ dport [0-9]\+ / dport EPHEMERAL /g;
  }

b match

:end
