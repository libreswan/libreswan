# fix up output containing random numbers

# 20000 has the same length as
# EPHEM

# IPv4
s/ \([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\):[2-6][0-9][0-9][0-9][0-9]$/ \1:EPHEM/g
s/ \([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\):[2-6][0-9][0-9][0-9][0-9]\([: ]\)/ \1:EPHEM\2/g
# IPv6
s/ \[\([0-9a-z:]*\)\]:[2-6][0-9][0-9][0-9][0-9]$/ \1:EPHEM/g
s/ \[\([0-9a-z:]*\)\]:[2-6][0-9][0-9][0-9][0-9]\([: ]\)/ \1:EPHEM\2/g

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
  s/ sport [2-6][0-9][0-9][0-9][0-9] / sport EPHEM /g
  s/ dport [2-6][0-9][0-9][0-9][0-9] / dport EPHEM /g;

b match

:end
