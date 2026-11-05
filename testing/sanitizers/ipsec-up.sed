# note this script need sed -n
# remove extra retransmits from the following ipsec commands
#
# ipsec auto --up road-east-psk

/^ ipsec up [[:alnum:]-]*$/ b match-ipsec-up
/^ ipsec auto --up [[:alnum:]-]*$/ b match-ipsec-up

b end-ipsec-up

:drop-ipsec-up

  # append line into PATTERN space; strip out current line
  N
  s/^.*\n//
  b match-ipsec-up

:next-ipsec-up

  # replace PATTERN space with next line (printing current)

  n

:match-ipsec-up

  /^[a-z][a-z]* #$/ b end-ipsec-up

  /retransmission; will wait/    b drop-ipsec-up
  /retransmitting .*; will wait/ b drop-ipsec-up

b next-ipsec-up

:end-ipsec-up
