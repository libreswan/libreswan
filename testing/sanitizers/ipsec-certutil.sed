# match: certutil

/^ certutil / b next-ipsec-certutil
/^ ipsec certutil / b next-ipsec-certutil

b end-ipsec-certutil

:drop-ipsec-certutil
  # read next line (drop current)
  N
  s/^.*\n//
  b match-ipsec-certutil

:next-ipsec-certutil
  # advance to next line (print current, read next)
  n

:match-ipsec-certutil
  # next command?
  /^[a-z][a-z]*#/ b end-ipsec-certutil
  /^[a-z][a-z]* #/ b end-ipsec-certutil

  # f28 gets different NSS errors compared to f22
  s/: SEC_ERROR_UNRECOGNIZED_OID: Unrecognized Object Identifier./: SEC_ERROR_.../
  s/: SEC_ERROR_INVALID_ARGS: security library: invalid arguments./: SEC_ERROR_.../

  # f28 prints full cert names; note that spaces matter!
  s/east_chain_int_2.testing.libreswan.org - Libreswan/east_chain_int_2                                  /
  s/west_chain_int_2.testing.libreswan.org - Libreswan/west_chain_int_2                                  /

b next-ipsec-certutil

:end-ipsec-certutil
