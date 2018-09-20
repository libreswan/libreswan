# match: certutil

/^ certutil / b match
b end

:match

  # print and read next line
  n
  /^[a-z]* #/ b end

  # f28 gets different NSS errors compared to f22
  s/: SEC_ERROR_UNRECOGNIZED_OID: Unrecognized Object Identifier./: SEC_ERROR_.../
  s/: SEC_ERROR_INVALID_ARGS: security library: invalid arguments./: SEC_ERROR_.../

  # f28 prints full cert names; note that spaces matter!
  s/east_chain_int_2.testing.libreswan.org - Libreswan/east_chain_int_2                                  /
  s/west_chain_int_2.testing.libreswan.org - Libreswan/west_chain_int_2                                  /

b match

:end
